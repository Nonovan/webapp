"""
Connection Manager for Security Assessment Tools.

This module provides standardized and secure connectivity to target systems
for security assessments. It handles authentication, connection pooling,
circuit breaking, exponential backoff, and secure credential management.

The connection manager supports multiple protocols and connection types
including SSH, HTTP/HTTPS, database connections, and cloud provider APIs.
"""

import abc
import logging
import os
import re
import socket
import ssl
import time
import uuid
from contextlib import contextmanager
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Callable, cast
from urllib.parse import urlparse

# Import error handling utilities for connection management
from .error_handlers import (
    handle_assessment_error,
    retry_operation,
    circuit_breaker,
    ExponentialBackoff,
    safe_execute,
    ValidationError
)

logger = logging.getLogger(__name__)

# Constants for connection management
DEFAULT_TIMEOUT = 30  # seconds
DEFAULT_RETRY_COUNT = 3
DEFAULT_RETRY_DELAY = 5  # seconds
DEFAULT_RETRY_BACKOFF = 2.0  # exponential factor
MAX_CONNECTIONS_PER_HOST = 10
CONNECTION_POOL_IDLE_TIMEOUT = 300  # seconds
DEFAULT_SSH_PORT = 22
DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443
DEFAULT_CONNECTION_RETRY_JITTER = 0.5  # 50% random jitter for retry intervals
DEFAULT_TCP_KEEPALIVE = 60  # seconds

# Import optional dependencies
try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    logger.warning("Requests package not available, HTTP connections will be limited")
    REQUESTS_AVAILABLE = False

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    logger.warning("Paramiko package not available, SSH connections will be limited")
    PARAMIKO_AVAILABLE = False

try:
    import psycopg2
    POSTGRES_AVAILABLE = True
except ImportError:
    logger.debug("Psycopg2 package not available, PostgreSQL connections will be limited")
    POSTGRES_AVAILABLE = False

try:
    import pymysql
    MYSQL_AVAILABLE = True
except ImportError:
    logger.debug("PyMySQL package not available, MySQL connections will be limited")
    MYSQL_AVAILABLE = False


class ConnectionType(Enum):
    """Supported connection types."""
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    POSTGRES = "postgres"
    MYSQL = "mysql"
    TCP = "tcp"
    MSSQL = "mssql"
    ORACLE = "oracle"
    MONGODB = "mongodb"
    REDIS = "redis"
    FTP = "ftp"
    SFTP = "sftp"
    SMB = "smb"
    LDAP = "ldap"
    RABBIT_MQ = "rabbitmq"
    KAFKA = "kafka"
    TELNET = "telnet"
    VNC = "vnc"
    RDP = "rdp"
    WINRM = "winrm"
    SNMP = "snmp"


class ConnectionProtocol(Enum):
    """High-level grouping of connection types."""
    WEB = "web"       # HTTP/HTTPS
    SHELL = "shell"   # SSH/Telnet
    DATABASE = "db"   # All database connections
    FILE = "file"     # FTP/SFTP/SMB
    DIRECTORY = "dir" # LDAP
    QUEUE = "queue"   # RabbitMQ/Kafka
    REMOTE = "remote" # VNC/RDP/WINRM
    NETWORK = "net"   # SNMP/TCP raw sockets


class ConnectionState(Enum):
    """Connection states."""
    INITIALIZED = "initialized"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    FAILED = "failed"
    CLOSED = "closed"
    CIRCUIT_OPEN = "circuit_open"  # Circuit breaker active


class ConnectionError(Exception):
    """Base exception for connection errors."""
    pass


class ConnectionTimeoutError(ConnectionError):
    """Exception for connection timeouts."""
    pass


class AuthenticationError(ConnectionError):
    """Exception for authentication failures."""
    pass


class ConnectionRefusedError(ConnectionError):
    """Exception for refused connections."""
    pass


class SSLError(ConnectionError):
    """Exception for SSL certificate issues."""
    pass


class ConnectionPool:
    """Manages a pool of connections to a specific host."""

    def __init__(
        self,
        host: str,
        max_connections: int = MAX_CONNECTIONS_PER_HOST,
        idle_timeout: int = CONNECTION_POOL_IDLE_TIMEOUT
    ):
        self.host = host
        self.max_connections = max_connections
        self.idle_timeout = idle_timeout
        self.connections: Dict[str, List[Tuple[Any, float]]] = {}  # key -> [(connection, last_used)]
        self.logger = logging.getLogger(f"{__name__}.ConnectionPool.{host}")
        self.logger.debug(
            f"Initialized connection pool for {host} with max_connections={max_connections}"
        )

    def get_connection(self, key: str) -> Optional[Any]:
        """
        Get a connection from the pool.

        Args:
            key: Unique key for this connection type (e.g., "https:443")

        Returns:
            A connection object if available, None otherwise
        """
        if key not in self.connections:
            return None

        now = time.time()
        # Clean expired connections
        self.connections[key] = [
            (conn, ts) for conn, ts in self.connections[key]
            if now - ts < self.idle_timeout
        ]

        if not self.connections[key]:
            return None

        # Get the least recently used connection
        connection, _ = self.connections[key].pop(0)
        self.logger.debug(f"Retrieved connection for {key} from pool")
        return connection

    def put_connection(self, key: str, connection: Any) -> None:
        """
        Return a connection to the pool.

        Args:
            key: Unique key for this connection type
            connection: Connection object to return to the pool
        """
        if key not in self.connections:
            self.connections[key] = []

        # If we've reached max connections, close the oldest one
        if len(self.connections[key]) >= self.max_connections:
            oldest_conn, _ = self.connections[key].pop(0)
            try:
                self._close_connection(oldest_conn)
                self.logger.debug(f"Closed oldest connection for {key} to stay within limits")
            except Exception as e:
                self.logger.warning(f"Failed to close connection: {str(e)}")

        # Add the new connection with current timestamp
        self.connections[key].append((connection, time.time()))
        self.logger.debug(f"Returned connection for {key} to pool")

    def cleanup(self) -> None:
        """
        Close and remove all idle connections.
        """
        now = time.time()
        closed_count = 0

        for key in list(self.connections.keys()):
            active_connections = []
            for conn, ts in self.connections[key]:
                if now - ts >= self.idle_timeout:
                    try:
                        self._close_connection(conn)
                        closed_count += 1
                    except Exception as e:
                        self.logger.warning(f"Failed to close idle connection: {str(e)}")
                else:
                    active_connections.append((conn, ts))

            if active_connections:
                self.connections[key] = active_connections
            else:
                del self.connections[key]

        if closed_count > 0:
            self.logger.debug(f"Cleaned up {closed_count} idle connections")

    def close_all(self) -> None:
        """
        Close and remove all connections.
        """
        closed_count = 0

        for key in list(self.connections.keys()):
            for conn, _ in self.connections[key]:
                try:
                    self._close_connection(conn)
                    closed_count += 1
                except Exception as e:
                    self.logger.warning(f"Failed to close connection: {str(e)}")

            del self.connections[key]

        if closed_count > 0:
            self.logger.info(f"Closed all {closed_count} connections for {self.host}")

    def _close_connection(self, connection: Any) -> None:
        """
        Close a specific connection based on its type.

        Args:
            connection: Connection object to close
        """
        # Handle various connection types
        if hasattr(connection, 'close') and callable(connection.close):
            connection.close()
        elif hasattr(connection, 'disconnect') and callable(connection.disconnect):
            connection.disconnect()
        elif hasattr(connection, 'logout') and callable(connection.logout):
            connection.logout()
        else:
            # Default case, just drop the reference
            pass


class ConnectionTarget:
    """
    Represents a target system for connections, with necessary connection parameters.
    """

    def __init__(
        self,
        host: str,
        port: Optional[int] = None,
        protocol: Optional[ConnectionType] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        key_file: Optional[str] = None,
        ssl_verify: bool = True,
        ca_cert: Optional[str] = None,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        db_name: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        **kwargs: Any
    ):
        """
        Initialize a connection target.

        Args:
            host: Target hostname or IP address
            port: Target port
            protocol: Connection protocol type
            username: Authentication username
            password: Authentication password
            key_file: Path to SSH key file
            ssl_verify: Whether to verify SSL certificates
            ca_cert: Path to CA certificate
            client_cert: Path to client certificate
            client_key: Path to client key
            db_name: Database name for database connections
            timeout: Connection timeout in seconds
            **kwargs: Additional connection parameters
        """
        self.host = host
        self.protocol = protocol
        self.username = username
        self.password = password
        self.key_file = key_file
        self.ssl_verify = ssl_verify
        self.ca_cert = ca_cert
        self.client_cert = client_cert
        self.client_key = client_key
        self.db_name = db_name
        self.timeout = timeout
        self.extra_params = kwargs

        # Set default port based on protocol if not specified
        if port is not None:
            self.port = port
        elif protocol:
            self.port = self._get_default_port(protocol)
        else:
            self.port = None

        # Generate a unique ID for this target
        self.target_id = str(uuid.uuid4())

    def _get_default_port(self, protocol: ConnectionType) -> int:
        """
        Get the default port for a given protocol.

        Args:
            protocol: Connection protocol

        Returns:
            Default port number
        """
        port_mapping = {
            ConnectionType.HTTP: 80,
            ConnectionType.HTTPS: 443,
            ConnectionType.SSH: 22,
            ConnectionType.POSTGRES: 5432,
            ConnectionType.MYSQL: 3306,
            ConnectionType.MSSQL: 1433,
            ConnectionType.ORACLE: 1521,
            ConnectionType.MONGODB: 27017,
            ConnectionType.REDIS: 6379,
            ConnectionType.FTP: 21,
            ConnectionType.SFTP: 22,
            ConnectionType.SMB: 445,
            ConnectionType.LDAP: 389,
            ConnectionType.RABBIT_MQ: 5672,
            ConnectionType.KAFKA: 9092,
            ConnectionType.TELNET: 23,
            ConnectionType.VNC: 5900,
            ConnectionType.RDP: 3389,
            ConnectionType.WINRM: 5985,
            ConnectionType.SNMP: 161,
            ConnectionType.TCP: None,  # No default for raw TCP
        }
        return port_mapping.get(protocol, 0)

    def as_url(self) -> str:
        """
        Get the target as a URL string.

        Returns:
            URL representation of the connection target
        """
        if not self.protocol or not self.port:
            return self.host

        # Build URL string based on connection type
        scheme = self.protocol.value
        port_str = f":{self.port}" if self.port else ""
        auth_part = ""

        if self.username:
            if self.password:
                auth_part = f"{self.username}:***@"
            else:
                auth_part = f"{self.username}@"

        # Add database name for database connections if present
        path_part = ""
        if self.db_name and self.protocol.value in [
            "postgres", "mysql", "mongodb", "mssql", "oracle"
        ]:
            path_part = f"/{self.db_name}"

        return f"{scheme}://{auth_part}{self.host}{port_str}{path_part}"

    def __str__(self) -> str:
        return self.as_url()


class ConnectionManager:
    """
    Manages connections to target systems with connection pooling, retry logic,
    and circuit breaking for fault tolerance.
    """

    def __init__(self,
                 default_timeout: int = DEFAULT_TIMEOUT,
                 retry_count: int = DEFAULT_RETRY_COUNT,
                 retry_delay: int = DEFAULT_RETRY_DELAY,
                 retry_backoff: float = DEFAULT_RETRY_BACKOFF,
                 pool_size: int = MAX_CONNECTIONS_PER_HOST,
                 credential_source: Optional[Dict[str, str]] = None):
        """
        Initialize the connection manager.

        Args:
            default_timeout: Default connection timeout in seconds
            retry_count: Default number of retries
            retry_delay: Initial delay between retries in seconds
            retry_backoff: Exponential backoff factor
            pool_size: Maximum connections per host
            credential_source: Source of credentials (overrides env vars)
        """
        self.default_timeout = default_timeout
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.retry_backoff = retry_backoff
        self.pool_size = pool_size
        self.credential_source = credential_source or {}

        # Connection pools keyed by host
        self.pools: Dict[str, ConnectionPool] = {}
        self.logger = logging.getLogger(f"{__name__}.ConnectionManager")
        self.logger.debug("Initialized connection manager")

        # Statistics for monitoring
        self.stats = {
            "connections_created": 0,
            "connections_reused": 0,
            "connection_failures": 0,
            "authentication_failures": 0,
            "timeouts": 0,
            "circuits_opened": 0,
            "successful_retries": 0
        }

    def _get_pool(self, host: str) -> ConnectionPool:
        """
        Get or create a connection pool for a host.

        Args:
            host: Target hostname or IP

        Returns:
            Connection pool for the host
        """
        if host not in self.pools:
            self.pools[host] = ConnectionPool(host, max_connections=self.pool_size)
        return self.pools[host]

    def _get_connection_key(self, target: ConnectionTarget) -> str:
        """
        Generate a unique key for a connection to use in the pool.

        Args:
            target: Connection target

        Returns:
            Unique connection key
        """
        # Format: protocol:port:username:dbname
        protocol_value = target.protocol.value if target.protocol else "unknown"
        port_value = str(target.port) if target.port else "default"
        user_value = target.username or "none"
        db_value = target.db_name or "none"

        return f"{protocol_value}:{port_value}:{user_value}:{db_value}"

    @contextmanager
    def get_connection(self, target: ConnectionTarget) -> Any:
        """
        Get a connection to the target with automatic pool management.

        Args:
            target: Connection target

        Yields:
            Connection object

        Raises:
            ConnectionError: If connection fails
        """
        connection = None
        pool = self._get_pool(target.host)
        conn_key = self._get_connection_key(target)

        # Try to get from pool first
        connection = pool.get_connection(conn_key)

        if connection:
            self.stats["connections_reused"] += 1
            self.logger.debug(f"Reusing pooled connection to {target}")
            try:
                yield connection
                # Return to pool if all went well
                pool.put_connection(conn_key, connection)
            except Exception:
                # On exception, don't return to pool and close
                try:
                    pool._close_connection(connection)
                except Exception as close_ex:
                    self.logger.warning(f"Error closing connection after exception: {close_ex}")
                raise
        else:
            # Create new connection
            try:
                connection = self._create_connection(target)
                self.stats["connections_created"] += 1
                yield connection
                # Return to pool if all went well
                pool.put_connection(conn_key, connection)
            except Exception as e:
                # Handle connection errors
                if isinstance(e, ConnectionTimeoutError):
                    self.stats["timeouts"] += 1
                elif isinstance(e, AuthenticationError):
                    self.stats["authentication_failures"] += 1
                else:
                    self.stats["connection_failures"] += 1

                self.logger.error(f"Connection error to {target}: {e}")

                # Ensure connection is closed if it was created
                if connection is not None:
                    try:
                        pool._close_connection(connection)
                    except Exception as close_ex:
                        self.logger.warning(f"Error closing failed connection: {close_ex}")

                # Re-raise the original exception
                raise

    @circuit_breaker(failure_threshold=5, reset_timeout=60.0, half_open_after=30.0)
    @retry_operation(max_retries=DEFAULT_RETRY_COUNT, delay=DEFAULT_RETRY_DELAY,
                     backoff=DEFAULT_RETRY_BACKOFF, jitter=DEFAULT_CONNECTION_RETRY_JITTER)
    def _create_connection(self, target: ConnectionTarget) -> Any:
        """
        Create a new connection to the target with retry and circuit breaking.

        Args:
            target: Connection target

        Returns:
            New connection object

        Raises:
            ConnectionError: If connection fails after retries
        """
        protocol = target.protocol

        if not protocol:
            # Try to guess the protocol from port
            protocol = self._guess_protocol_from_port(target.port)
            if not protocol:
                raise ConnectionError(f"Unable to determine connection protocol for {target}")

        # Handle different protocol types
        try:
            # Set default timeout if not specified
            timeout = target.timeout or self.default_timeout

            if protocol == ConnectionType.HTTP:
                return self._create_http_connection(target, ssl_enabled=False)
            elif protocol == ConnectionType.HTTPS:
                return self._create_http_connection(target, ssl_enabled=True)
            elif protocol == ConnectionType.SSH:
                return self._create_ssh_connection(target)
            elif protocol == ConnectionType.POSTGRES:
                return self._create_postgres_connection(target)
            elif protocol == ConnectionType.MYSQL:
                return self._create_mysql_connection(target)
            elif protocol == ConnectionType.TCP:
                return self._create_tcp_connection(target)
            # Add additional protocols as needed
            else:
                raise ConnectionError(f"Unsupported connection protocol: {protocol.value}")

        except socket.timeout:
            raise ConnectionTimeoutError(f"Connection to {target} timed out after {timeout} seconds")
        except ssl.SSLError as e:
            raise SSLError(f"SSL error connecting to {target}: {str(e)}")
        except paramiko.AuthenticationException as e:
            raise AuthenticationError(f"Authentication failed for {target}: {str(e)}")
        except paramiko.SSHException as e:
            raise ConnectionError(f"SSH error for {target}: {str(e)}")
        except (psycopg2.OperationalError, pymysql.err.OperationalError) as e:
            if "authentication" in str(e).lower():
                raise AuthenticationError(f"Database authentication failed for {target}: {str(e)}")
            raise ConnectionError(f"Database connection error for {target}: {str(e)}")
        except socket.error as e:
            if e.errno == 111:  # Connection refused
                raise ConnectionRefusedError(f"Connection refused to {target}")
            raise ConnectionError(f"Socket error for {target}: {str(e)}")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {target}: {str(e)}")

    def _guess_protocol_from_port(self, port: Optional[int]) -> Optional[ConnectionType]:
        """
        Guess protocol from port number.

        Args:
            port: Port number

        Returns:
            Guessed connection type or None
        """
        if port is None:
            return None

        port_map = {
            22: ConnectionType.SSH,
            80: ConnectionType.HTTP,
            443: ConnectionType.HTTPS,
            5432: ConnectionType.POSTGRES,
            3306: ConnectionType.MYSQL,
            1433: ConnectionType.MSSQL,
            1521: ConnectionType.ORACLE,
            27017: ConnectionType.MONGODB,
            6379: ConnectionType.REDIS,
            21: ConnectionType.FTP,
            445: ConnectionType.SMB,
            389: ConnectionType.LDAP,
            5672: ConnectionType.RABBIT_MQ,
            9092: ConnectionType.KAFKA,
            23: ConnectionType.TELNET,
            5900: ConnectionType.VNC,
            3389: ConnectionType.RDP,
            5985: ConnectionType.WINRM,
            161: ConnectionType.SNMP
        }

        return port_map.get(port)

    def _create_http_connection(self, target: ConnectionTarget, ssl_enabled: bool = True) -> 'requests.Session':
        """
        Create an HTTP/HTTPS connection using requests.

        Args:
            target: Connection target
            ssl_enabled: Whether to use HTTPS

        Returns:
            Requests session object

        Raises:
            ConnectionError: If connection cannot be established
        """
        if not REQUESTS_AVAILABLE:
            raise ConnectionError("Requests library is required for HTTP/HTTPS connections")

        self.logger.debug(f"Creating {'HTTPS' if ssl_enabled else 'HTTP'} connection to {target}")

        # Configure session with retry logic
        session = requests.Session()

        # Configure retry with exponential backoff
        retry_strategy = Retry(
            total=self.retry_count,
            backoff_factor=self.retry_delay,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )

        # Configure adapter with retry strategy
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Configure SSL verification
        if ssl_enabled:
            if target.ssl_verify:
                if target.ca_cert:
                    session.verify = target.ca_cert
                else:
                    session.verify = True
            else:
                session.verify = False
                # Suppress InsecureRequestWarning
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Configure client certificate
        if ssl_enabled and target.client_cert:
            if target.client_key:
                session.cert = (target.client_cert, target.client_key)
            else:
                session.cert = target.client_cert

        # Configure authentication
        if target.username:
            if target.password:
                session.auth = (target.username, target.password)

        # Set timeout
        session.timeout = target.timeout or self.default_timeout

        # Add headers from extra params
        if "headers" in target.extra_params:
            session.headers.update(target.extra_params["headers"])

        # Test connection
        protocol = "https" if ssl_enabled else "http"
        url = f"{protocol}://{target.host}"
        if target.port:
            url += f":{target.port}"

        # Only perform a HEAD request to verify connectivity
        try:
            session.head(url, timeout=target.timeout or self.default_timeout)
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"Initial connection test to {url} failed: {e}")
            # We'll continue anyway as the session might still be usable for other paths

        return session

    def _create_ssh_connection(self, target: ConnectionTarget) -> 'paramiko.SSHClient':
        """
        Create an SSH connection using paramiko.

        Args:
            target: Connection target

        Returns:
            Paramiko SSH client

        Raises:
            ConnectionError: If connection cannot be established
        """
        if not PARAMIKO_AVAILABLE:
            raise ConnectionError("Paramiko library is required for SSH connections")

        self.logger.debug(f"Creating SSH connection to {target}")

        client = paramiko.SSHClient()

        # Set up host key policy
        if target.extra_params.get("auto_add_key", False):
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            known_hosts = target.extra_params.get("known_hosts_file", None)
            if known_hosts:
                client.load_host_keys(known_hosts)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

        # Prepare connection parameters
        connect_params = {
            "hostname": target.host,
            "port": target.port or DEFAULT_SSH_PORT,
            "timeout": target.timeout or self.default_timeout
        }

        # Handle authentication
        if target.username:
            connect_params["username"] = target.username

            if target.key_file:
                # Authenticate using SSH key
                key_pass = target.extra_params.get("key_password", None)

                # Try loading key with and without password
                try:
                    if key_pass:
                        pkey = paramiko.RSAKey.from_private_key_file(
                            target.key_file, password=key_pass
                        )
                    else:
                        pkey = paramiko.RSAKey.from_private_key_file(target.key_file)
                    connect_params["pkey"] = pkey
                except paramiko.ssh_exception.PasswordRequiredException:
                    raise AuthenticationError("Private key requires a password")
                except Exception as e:
                    raise ConnectionError(f"Failed to load SSH key: {str(e)}")

            elif target.password:
                # Authenticate using password
                connect_params["password"] = target.password

        # Connect
        try:
            client.connect(**connect_params)
            return client
        except Exception as e:
            raise ConnectionError(f"SSH connection failed: {str(e)}")

    def _create_postgres_connection(self, target: ConnectionTarget) -> 'psycopg2.connection':
        """
        Create a PostgreSQL database connection.

        Args:
            target: Connection target

        Returns:
            PostgreSQL connection

        Raises:
            ConnectionError: If connection cannot be established
        """
        if not POSTGRES_AVAILABLE:
            raise ConnectionError("Psycopg2 library is required for PostgreSQL connections")

        self.logger.debug(f"Creating PostgreSQL connection to {target}")

        # Prepare connection parameters
        connect_params = {
            "host": target.host,
            "port": target.port or 5432,
            "connect_timeout": target.timeout or self.default_timeout
        }

        # Add authentication if provided
        if target.username:
            connect_params["user"] = target.username

        if target.password:
            connect_params["password"] = target.password

        if target.db_name:
            connect_params["dbname"] = target.db_name
        else:
            connect_params["dbname"] = "postgres"  # Default DB

        # Configure SSL if enabled
        if target.ssl_verify:
            connect_params["sslmode"] = "verify-full"
            if target.ca_cert:
                connect_params["sslrootcert"] = target.ca_cert
        elif target.extra_params.get("ssl_enabled", False):
            connect_params["sslmode"] = "require"

        # Add client certificate if provided
        if target.client_cert:
            connect_params["sslcert"] = target.client_cert

        if target.client_key:
            connect_params["sslkey"] = target.client_key

        # Connect
        try:
            conn = psycopg2.connect(**connect_params)
            return conn
        except Exception as e:
            raise ConnectionError(f"PostgreSQL connection failed: {str(e)}")

    def _create_mysql_connection(self, target: ConnectionTarget) -> 'pymysql.Connection':
        """
        Create a MySQL database connection.

        Args:
            target: Connection target

        Returns:
            MySQL connection

        Raises:
            ConnectionError: If connection cannot be established
        """
        if not MYSQL_AVAILABLE:
            raise ConnectionError("PyMySQL library is required for MySQL connections")

        self.logger.debug(f"Creating MySQL connection to {target}")

        # Prepare connection parameters
        connect_params = {
            "host": target.host,
            "port": target.port or 3306,
            "connect_timeout": target.timeout or self.default_timeout
        }

        # Add authentication if provided
        if target.username:
            connect_params["user"] = target.username

        if target.password:
            connect_params["password"] = target.password

        if target.db_name:
            connect_params["database"] = target.db_name

        # Configure SSL if enabled
        if target.ssl_verify or target.extra_params.get("ssl_enabled", False):
            ssl_params = {}

            if target.ca_cert:
                ssl_params["ca"] = target.ca_cert

            if target.client_cert:
                ssl_params["cert"] = target.client_cert

            if target.client_key:
                ssl_params["key"] = target.client_key

            connect_params["ssl"] = ssl_params

        # Connect
        try:
            conn = pymysql.connect(**connect_params)
            return conn
        except Exception as e:
            raise ConnectionError(f"MySQL connection failed: {str(e)}")

    def _create_tcp_connection(self, target: ConnectionTarget) -> socket.socket:
        """
        Create a raw TCP socket connection.

        Args:
            target: Connection target

        Returns:
            TCP socket

        Raises:
            ConnectionError: If connection cannot be established
        """
        self.logger.debug(f"Creating TCP socket connection to {target}")

        if not target.port:
            raise ValueError("Port is required for TCP connections")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set timeout
        sock.settimeout(target.timeout or self.default_timeout)

        # Enable TCP keepalive
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        # Connect
        try:
            sock.connect((target.host, target.port))
            return sock
        except Exception as e:
            sock.close()
            raise ConnectionError(f"TCP connection failed: {str(e)}")

    def cleanup_pools(self) -> None:
        """
        Clean up idle connections in all pools.
        """
        for pool in self.pools.values():
            pool.cleanup()
        self.logger.debug("Cleaned up idle connections in all pools")

    def close_all_connections(self) -> None:
        """
        Close all connections in all pools.
        """
        for pool in self.pools.values():
            pool.close_all()
        self.pools.clear()
        self.logger.info("Closed all connections")

    def get_stats(self) -> Dict[str, int]:
        """
        Get connection statistics.

        Returns:
            Dictionary of connection statistics
        """
        return self.stats.copy()

    def reset_stats(self) -> None:
        """Reset connection statistics."""
        for key in self.stats:
            self.stats[key] = 0
        self.logger.debug("Reset connection statistics")

    def test_connectivity(self, target: ConnectionTarget) -> bool:
        """
        Test connectivity to a target without establishing a full connection.

        Args:
            target: Connection target

        Returns:
            True if target is reachable, False otherwise
        """
        port = target.port
        if port is None:
            if target.protocol:
                port = self._get_default_port(target.protocol)
            else:
                # Default to HTTPS
                port = 443

        self.logger.debug(f"Testing basic connectivity to {target.host}:{port}")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(target.timeout or self.default_timeout)
            sock.connect((target.host, port))
            sock.close()
            return True
        except (socket.timeout, socket.error):
            return False


# Global connection manager instance
_connection_manager: Optional[ConnectionManager] = None


def get_connection_manager() -> ConnectionManager:
    """
    Get the global connection manager instance.

    Returns:
        Global connection manager
    """
    global _connection_manager
    if _connection_manager is None:
        _connection_manager = ConnectionManager()
    return _connection_manager


@contextmanager
def secure_connect(target: Union[ConnectionTarget, Dict[str, Any]]) -> Any:
    """
    Context manager for secure connections to target systems.

    Args:
        target: Connection target or dictionary of connection parameters

    Yields:
        Connection object
    """
    # Convert dict to ConnectionTarget if needed
    if isinstance(target, dict):
        protocol = None
        if "protocol" in target:
            protocol_value = target["protocol"]
            if isinstance(protocol_value, str):
                try:
                    protocol = ConnectionType(protocol_value)
                except ValueError:
                    protocol = None
            elif isinstance(protocol_value, ConnectionType):
                protocol = protocol_value

        target = ConnectionTarget(
            host=target["host"],
            port=target.get("port"),
            protocol=protocol,
            username=target.get("username"),
            password=target.get("password"),
            key_file=target.get("key_file"),
            ssl_verify=target.get("ssl_verify", True),
            ca_cert=target.get("ca_cert"),
            client_cert=target.get("client_cert"),
            client_key=target.get("client_key"),
            db_name=target.get("db_name"),
            timeout=target.get("timeout"),
            **{k: v for k, v in target.items() if k not in [
                "host", "port", "protocol", "username", "password",
                "key_file", "ssl_verify", "ca_cert", "client_cert",
                "client_key", "db_name", "timeout"
            ]}
        )

    # Get connection from manager
    conn_manager = get_connection_manager()
    with conn_manager.get_connection(target) as conn:
        yield conn


def test_connectivity(host: str, port: Optional[int] = None,
                     timeout: int = DEFAULT_TIMEOUT) -> bool:
    """
    Test basic connectivity to a host and port.

    Args:
        host: Target hostname or IP
        port: Target port
        timeout: Connection timeout in seconds

    Returns:
        True if target is reachable, False otherwise
    """
    target = ConnectionTarget(host=host, port=port, timeout=timeout)
    conn_manager = get_connection_manager()
    return conn_manager.test_connectivity(target)


def get_connection_for_target(target_spec: str, **kwargs: Any) -> Any:
    """
    Get a connection for a target specified as a URL string.

    Args:
        target_spec: Target specification as URL (e.g., "https://example.com:443")
        **kwargs: Additional connection parameters

    Returns:
        Connection object

    Raises:
        ValueError: If target specification is invalid
    """
    try:
        parsed = urlparse(target_spec)

        # Extract protocol
        if parsed.scheme:
            try:
                protocol = ConnectionType(parsed.scheme)
            except ValueError:
                raise ValueError(f"Unsupported protocol: {parsed.scheme}")
        else:
            protocol = None

        # Extract authentication if present
        username = None
        password = None
        if parsed.username:
            username = parsed.username
            if parsed.password:
                password = parsed.password

        # Create target
        target = ConnectionTarget(
            host=parsed.hostname or target_spec,
            port=parsed.port,
            protocol=protocol,
            username=username,
            password=password,
            db_name=parsed.path.lstrip("/") or None if parsed.path else None,
            **kwargs
        )

        # Return connection context
        return secure_connect(target)
    except Exception as e:
        raise ValueError(f"Invalid target specification '{target_spec}': {str(e)}")


def cleanup_connections() -> None:
    """Clean up idle connections in all pools."""
    conn_manager = get_connection_manager()
    conn_manager.cleanup_pools()


def close_all_connections() -> None:
    """Close all connections."""
    conn_manager = get_connection_manager()
    conn_manager.close_all_connections()


def parse_connection_string(conn_string: str) -> Dict[str, Any]:
    """
    Parse a connection string into connection parameters.

    Args:
        conn_string: Connection string (e.g., "postgresql://user:pass@host:port/dbname")

    Returns:
        Dictionary of connection parameters

    Raises:
        ValueError: If connection string is invalid
    """
    try:
        parsed = urlparse(conn_string)
        result = {
            "protocol": parsed.scheme,
            "host": parsed.hostname,
        }

        if parsed.port:
            result["port"] = parsed.port

        if parsed.username:
            result["username"] = parsed.username

        if parsed.password:
            result["password"] = parsed.password

        if parsed.path and parsed.path.strip("/"):
            result["db_name"] = parsed.path.strip("/")

        # Parse query parameters
        if parsed.query:
            import urllib.parse
            params = dict(urllib.parse.parse_qsl(parsed.query))

            # Convert common parameters
            if "ssl" in params:
                result["ssl_verify"] = params["ssl"].lower() in ("true", "yes", "1")

            if "sslrootcert" in params:
                result["ca_cert"] = params["sslrootcert"]

            if "sslcert" in params:
                result["client_cert"] = params["sslcert"]

            if "sslkey" in params:
                result["client_key"] = params["sslkey"]

            if "connect_timeout" in params:
                try:
                    result["timeout"] = int(params["connect_timeout"])
                except ValueError:
                    pass

            # Add remaining parameters to extra_params
            for key, value in params.items():
                if key not in ("ssl", "sslrootcert", "sslcert", "sslkey", "connect_timeout"):
                    if "extra_params" not in result:
                        result["extra_params"] = {}
                    result["extra_params"][key] = value

        return result
    except Exception as e:
        raise ValueError(f"Invalid connection string: {str(e)}")


def is_valid_hostname(hostname: str) -> bool:
    """
    Check if a hostname is valid.

    Args:
        hostname: Hostname to check

    Returns:
        True if hostname is valid, False otherwise
    """
    if not hostname or len(hostname) > 255:
        return False

    if hostname[-1] == ".":
        # Strip trailing dot
        hostname = hostname[:-1]

    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)

    return all(allowed.match(x) for x in hostname.split("."))


def is_valid_ipv4_address(ip: str) -> bool:
    """
    Check if an IP address is a valid IPv4 address.

    Args:
        ip: IP address to check

    Returns:
        True if IP is valid IPv4 address, False otherwise
    """
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except (socket.error, TypeError):
        return False


def is_valid_ipv6_address(ip: str) -> bool:
    """
    Check if an IP address is a valid IPv6 address.

    Args:
        ip: IP address to check

    Returns:
        True if IP is valid IPv6 address, False otherwise
    """
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except (socket.error, TypeError):
        return False


def is_valid_connection_target(host: str, port: Optional[int] = None) -> bool:
    """
    Validate if a host and port form a valid connection target.

    Args:
        host: Target hostname or IP
        port: Target port

    Returns:
        True if valid, False otherwise
    """
    # Check host
    if not host:
        return False

    # Check if it's an IP address (v4 or v6)
    if not (is_valid_ipv4_address(host) or is_valid_ipv6_address(host)):
        # Check if it's a valid hostname
        if not is_valid_hostname(host):
            return False

    # Check port if provided
    if port is not None:
        if not isinstance(port, int):
            return False
        if port < 1 or port > 65535:
            return False

    return True
