"""
Cloud provider model for managing cloud service providers.

This module provides the CloudProvider model which represents different cloud service
providers (AWS, Azure, GCP, etc.) and manages their authentication, configuration,
and resource allocation within the platform.
"""

import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Union
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app

from extensions import db, cache
from core.metrics import metrics
from core.security_utils import decrypt_data, encrypt_data
from models.base import BaseModel, AuditableMixin


class CloudProvider(BaseModel, AuditableMixin):
    """
    Model representing a cloud service provider.

    This model tracks cloud providers with their configuration, authentication
    credentials (encrypted), and monitoring settings to enable multi-cloud
    resource management and metrics collection.

    Attributes:
        id: Primary key
        name: Provider name (AWS, Azure, GCP, etc.)
        provider_type: Type identifier (aws, azure, gcp, etc.)
        is_active: Whether the provider is currently active
        credentials: Encrypted JSON data for authentication
        config: JSON configuration data
        default_region: Default region for resource deployment
        api_endpoint: Custom API endpoint if needed
        monitoring_enabled: Whether monitoring is enabled
        quota: JSON data containing quota information
    """
    __tablename__ = 'cloud_providers'

    # Provider types
    TYPE_AWS = 'aws'
    TYPE_AZURE = 'azure'
    TYPE_GCP = 'gcp'
    TYPE_CUSTOM = 'custom'

    PROVIDER_TYPES = [TYPE_AWS, TYPE_AZURE, TYPE_GCP, TYPE_CUSTOM]

    # Table definition
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    provider_type = db.Column(db.String(32), nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    credentials = db.Column(db.Text, nullable=True)  # Encrypted
    config = db.Column(MutableDict.as_mutable(db.JSON), default=dict, nullable=False)
    default_region = db.Column(db.String(64), nullable=True)
    api_endpoint = db.Column(db.String(255), nullable=True)
    monitoring_enabled = db.Column(db.Boolean, default=True, nullable=False)
    quota = db.Column(MutableDict.as_mutable(db.JSON), default=dict, nullable=False)
    last_scan_time = db.Column(db.DateTime, nullable=True)
    last_scan_status = db.Column(db.String(32), nullable=True)

    # Relationships defined in reverse in CloudResource model

    def __init__(self, name: str, provider_type: str, default_region: Optional[str] = None,
                credentials: Optional[str] = None, config: Optional[Dict] = None,
                api_endpoint: Optional[str] = None, monitoring_enabled: bool = True,
                quota: Optional[Dict] = None):
        """
        Initialize a CloudProvider instance.

        Args:
            name: Provider name
            provider_type: Type of provider (aws, azure, gcp, etc.)
            default_region: Default region for resource deployment
            credentials: Encrypted credentials JSON string
            config: Provider configuration
            api_endpoint: Custom API endpoint
            monitoring_enabled: Whether monitoring is enabled
            quota: Provider quota information

        Raises:
            ValueError: If provider_type is not one of the allowed types
        """
        self.name = name
        if provider_type not in self.PROVIDER_TYPES:
            raise ValueError(f"Invalid provider type. Must be one of: {', '.join(self.PROVIDER_TYPES)}")
        self.provider_type = provider_type
        self.default_region = default_region
        self.credentials = credentials
        self.config = config or {}
        self.api_endpoint = api_endpoint
        self.monitoring_enabled = monitoring_enabled
        self.quota = quota or {}

    def to_dict(self, include_credentials: bool = False) -> Dict[str, Any]:
        """
        Convert provider to dictionary for API responses.

        Args:
            include_credentials: Whether to include encrypted credentials

        Returns:
            Dict[str, Any]: Dictionary with provider data
        """
        data = {
            'id': self.id,
            'name': self.name,
            'provider_type': self.provider_type,
            'is_active': self.is_active,
            'default_region': self.default_region,
            'api_endpoint': self.api_endpoint,
            'monitoring_enabled': self.monitoring_enabled,
            'config': self.config,
            'quota': self.quota,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_scan_time': self.last_scan_time.isoformat() if self.last_scan_time else None,
            'last_scan_status': self.last_scan_status,
        }

        if include_credentials:
            data['credentials'] = self.credentials

        return data

    def get_credentials_dict(self) -> Dict[str, Any]:
        """
        Get decrypted credentials as dictionary.

        Returns:
            Dict[str, Any]: Decrypted credentials as dictionary or empty dict if error
        """
        if not self.credentials:
            return {}

        try:
            decrypted = decrypt_data(self.credentials)
            return json.loads(decrypted)
        except json.JSONDecodeError as e:
            current_app.logger.error(f"Failed to parse decrypted provider credentials for {self.name}: {e}")
            return {}
        except ValueError as e:
            current_app.logger.error(f"Failed to decrypt provider credentials for {self.name}: {e}")
            return {}
        except Exception as e:
            current_app.logger.error(f"Unexpected error accessing provider credentials for {self.name}: {e}")
            return {}

    def set_credentials_dict(self, credentials_dict: Dict[str, Any]) -> bool:
        """
        Encrypt and set credentials from dictionary.

        Args:
            credentials_dict: Dictionary of credentials to encrypt and store

        Returns:
            bool: True if successful, False otherwise
        """
        if not isinstance(credentials_dict, dict):
            current_app.logger.error(f"Invalid credentials type for {self.name}: expected dict, got {type(credentials_dict)}")
            return False

        try:
            json_str = json.dumps(credentials_dict)
            self.credentials = encrypt_data(json_str)

            # If monitoring is enabled, attempt credential validation
            if self.monitoring_enabled and self.is_active:
                validation_result = self._validate_credentials(credentials_dict)
                if not validation_result['valid']:
                    current_app.logger.warning(
                        f"Credentials for {self.name} ({self.provider_type}) were saved but failed validation: "
                        f"{validation_result['message']}"
                    )

            return True
        except TypeError as e:
            current_app.logger.error(f"Failed to serialize provider credentials for {self.name}: {e}")
            return False
        except ValueError as e:
            current_app.logger.error(f"Failed to encrypt provider credentials for {self.name}: {e}")
            return False
        except Exception as e:
            current_app.logger.error(f"Unexpected error storing credentials for {self.name}: {e}", exc_info=True)
            return False

    def _validate_credentials(self, credentials_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate provider credentials by attempting to connect to the cloud provider.

        Args:
            credentials_dict: Decrypted credentials dictionary

        Returns:
            Dict containing validation results with 'valid' boolean and 'message' string
        """
        try:
            if self.provider_type == self.TYPE_AWS:
                return self._validate_aws_credentials(credentials_dict)
            elif self.provider_type == self.TYPE_AZURE:
                return self._validate_azure_credentials(credentials_dict)
            elif self.provider_type == self.TYPE_GCP:
                return self._validate_gcp_credentials(credentials_dict)
            else:
                return {'valid': False, 'message': f"Unsupported provider type: {self.provider_type}"}
        except KeyError as e:
            current_app.logger.error(f"Missing required credential field for {self.provider_type}: {str(e)}")
            return {'valid': False, 'message': f"Missing required credential field: {str(e)}"}
        except ValueError as e:
            current_app.logger.error(f"Invalid credential value for {self.provider_type}: {str(e)}")
            return {'valid': False, 'message': f"Invalid credential value: {str(e)}"}
        except Exception as e:
            current_app.logger.error(f"Error validating credentials for {self.provider_type}: {str(e)}", exc_info=True)
            return {'valid': False, 'message': f"Validation error: {str(e)}"}

    def _validate_aws_credentials(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate AWS credentials by connecting to the AWS API.

        Args:
            credentials: AWS credentials dictionary

        Returns:
            Dict with validation status and message
        """
        try:
            # Only import boto3 when needed to avoid dependency issues
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError

            # Required fields check
            required_fields = ['access_key_id', 'secret_access_key']
            for field in required_fields:
                if not credentials.get(field):
                    return {'valid': False, 'message': f"Missing required AWS credential field: {field}"}

            session = boto3.session.Session(
                aws_access_key_id=credentials.get('access_key_id'),
                aws_secret_access_key=credentials.get('secret_access_key'),
                region_name=self.default_region or 'us-east-1'
            )

            # Try to list regions as a simple validation
            client = session.client('ec2')
            client.describe_regions()

            return {'valid': True, 'message': 'AWS credentials validated successfully'}
        except ImportError:
            return {'valid': False, 'message': 'AWS SDK (boto3) not installed'}
        except NoCredentialsError:
            return {'valid': False, 'message': 'Missing AWS credentials'}
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            return {'valid': False, 'message': f"AWS API error ({error_code}): {error_message}"}
        except Exception as e:
            return {'valid': False, 'message': f"AWS credential validation error: {str(e)}"}

    def _validate_azure_credentials(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate Azure credentials by connecting to the Azure API.

        Args:
            credentials: Azure credentials dictionary

        Returns:
            Dict with validation status and message
        """
        try:
            # Only import Azure SDK when needed
            from azure.identity import ClientSecretCredential
            from azure.mgmt.resource import ResourceManagementClient
            from azure.core.exceptions import ClientAuthenticationError

            # Required fields check
            required_fields = ['tenant_id', 'client_id', 'client_secret', 'subscription_id']
            for field in required_fields:
                if not credentials.get(field):
                    return {'valid': False, 'message': f"Missing required Azure credential field: {field}"}

            credential = ClientSecretCredential(
                tenant_id=credentials.get('tenant_id'),
                client_id=credentials.get('client_id'),
                client_secret=credentials.get('client_secret')
            )

            # Try to create a client and list resource groups
            resource_client = ResourceManagementClient(credential, credentials.get('subscription_id'))
            list(resource_client.resource_groups.list())

            return {'valid': True, 'message': 'Azure credentials validated successfully'}
        except ImportError:
            return {'valid': False, 'message': 'Azure SDK not installed'}
        except ClientAuthenticationError as e:
            return {'valid': False, 'message': f"Azure authentication error: {str(e)}"}
        except ValueError as e:
            return {'valid': False, 'message': f"Invalid Azure credential format: {str(e)}"}
        except KeyError as e:
            return {'valid': False, 'message': f"Missing credential field: {str(e)}"}
        except Exception as e:
            return {'valid': False, 'message': f"Azure credential validation error: {str(e)}"}

    def _validate_gcp_credentials(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate GCP credentials by connecting to the GCP API.

        Args:
            credentials: GCP credentials dictionary

        Returns:
            Dict with validation status and message
        """
        try:
            # Only import GCP libraries when needed
            from google.oauth2 import service_account
            from google.cloud import storage
            from google.api_core.exceptions import GoogleAPIError

            # GCP usually uses a service account key JSON file,
            # which we would have stored in the credentials JSON
            if 'service_account_info' not in credentials:
                return {'valid': False, 'message': 'Missing service_account_info in credentials'}

            # Required fields in the service account info
            service_account_info = credentials.get('service_account_info')
            required_fields = ['client_email', 'private_key', 'project_id']
            for field in required_fields:
                if field not in service_account_info:
                    return {'valid': False, 'message': f"Missing required field in service account info: {field}"}

            # Create credentials from service account info
            gcp_credentials = service_account.Credentials.from_service_account_info(service_account_info)

            # Try to list buckets as a simple validation
            storage_client = storage.Client(credentials=gcp_credentials)
            list(storage_client.list_buckets(max_results=1))

            return {'valid': True, 'message': 'GCP credentials validated successfully'}
        except ImportError:
            return {'valid': False, 'message': 'Google Cloud SDK not installed'}
        except GoogleAPIError as e:
            return {'valid': False, 'message': f"GCP API error: {str(e)}"}
        except (KeyError, ValueError, json.JSONDecodeError) as e:
            return {'valid': False, 'message': f"GCP credential validation error: {str(e)}"}
        except Exception as e:
            return {'valid': False, 'message': f"GCP credential validation error: {str(e)}"}

    @classmethod
    def get_by_type(cls, provider_type: str, active_only: bool = True) -> List['CloudProvider']:
        """
        Get providers by provider type.

        Args:
            provider_type: Type of provider to filter by
            active_only: Whether to return only active providers

        Returns:
            List[CloudProvider]: List of matching cloud providers
        """
        try:
            query = cls.query.filter_by(provider_type=provider_type)
            if active_only:
                query = query.filter_by(is_active=True)
            return query.all()
        except SQLAlchemyError as e:
            current_app.logger.error(f"Database error in get_by_type: {str(e)}")
            return []

    @classmethod
    def get_provider_regions(cls, provider_id: int) -> List[str]:
        """
        Get available regions for a provider.

        Args:
            provider_id: ID of the cloud provider

        Returns:
            List of region identifiers for the specified provider
        """
        try:
            provider = cls.query.get(provider_id)
            if not provider:
                return []

            cache_key = f'provider_regions:{provider_id}'
            cached = cache.get(cache_key)
            if cached:
                return cached

            # Try to get real regions from cloud provider API
            regions = provider.fetch_provider_regions()

            # If we couldn't get real regions, fall back to default list
            if not regions:
                regions_map = {
                    cls.TYPE_AWS: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
                                'ca-central-1', 'eu-west-1', 'eu-west-2', 'eu-central-1',
                                'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1',
                                'sa-east-1'],
                    cls.TYPE_AZURE: ['eastus', 'eastus2', 'westus', 'westus2', 'centralus',
                                   'northeurope', 'westeurope', 'southeastasia',
                                   'eastasia', 'japaneast', 'brazilsouth', 'australiaeast'],
                    cls.TYPE_GCP: ['us-central1', 'us-east1', 'us-east4', 'us-west1',
                                 'us-west2', 'northamerica-northeast1', 'europe-west1',
                                 'europe-west2', 'europe-west4', 'asia-east1',
                                 'asia-southeast1', 'australia-southeast1'],
                }
                regions = regions_map.get(provider.provider_type, [])

            # Cache regions for 1 hour
            if regions:
                cache.set(cache_key, regions, timeout=3600)

            # Track metric for region discovery
            if hasattr(metrics, 'gauge'):
                metrics.gauge(
                    'cloud_provider_regions_count',
                    len(regions),
                    {'provider_type': provider.provider_type, 'provider_id': str(provider_id)}
                )

            return regions
        except SQLAlchemyError as e:
            current_app.logger.error(f"Database error in get_provider_regions: {str(e)}")
            return []
        except Exception as e:
            current_app.logger.error(f"Unexpected error in get_provider_regions: {str(e)}")
            return []

    def fetch_provider_regions(self) -> List[str]:
        """
        Fetch available regions directly from the cloud provider API.

        Returns:
            List of region identifiers
        """
        try:
            credentials = self.get_credentials_dict()
            if not credentials:
                current_app.logger.warning(f"No credentials available for provider {self.name}")
                return []

            if self.provider_type == self.TYPE_AWS:
                return self._fetch_aws_regions(credentials)
            elif self.provider_type == self.TYPE_AZURE:
                return self._fetch_azure_regions(credentials)
            elif self.provider_type == self.TYPE_GCP:
                return self._fetch_gcp_regions(credentials)
            else:
                current_app.logger.warning(f"Unknown provider type: {self.provider_type}")
                return []
        except KeyError as e:
            current_app.logger.error(f"Missing credential field for {self.provider_type}: {str(e)}")
            return []
        except ImportError as e:
            current_app.logger.error(f"Required module not available for {self.provider_type}: {str(e)}")
            return []
        except (ValueError, TypeError) as e:
            current_app.logger.error(f"Invalid credential format for {self.provider_type}: {str(e)}")
            return []
        except ConnectionError as e:
            current_app.logger.error(f"Connection error reaching {self.provider_type} API: {str(e)}")
            return []
        except Exception as e:
            current_app.logger.error(f"Unexpected error fetching regions for {self.provider_type}: {str(e)}", exc_info=True)
            return []

    def _fetch_aws_regions(self, credentials: Dict[str, Any]) -> List[str]:
        """
        Fetch AWS regions using the AWS API.

        Args:
            credentials: AWS credentials dictionary

        Returns:
            List[str]: List of AWS region names
        """
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError

            session = boto3.session.Session(
                aws_access_key_id=credentials.get('access_key_id'),
                aws_secret_access_key=credentials.get('secret_access_key'),
                region_name=self.default_region or 'us-east-1'
            )

            ec2 = session.client('ec2')
            response = ec2.describe_regions()

            # Update last scan time and status
            self.last_scan_time = datetime.utcnow()
            self.last_scan_status = 'success'
            db.session.commit()

            return [region['RegionName'] for region in response['Regions']]
        except ImportError as e:
            current_app.logger.warning(f"Failed to fetch AWS regions due to missing dependencies: {str(e)}")
            self._update_scan_status('dependency_error')
            return []
        except NoCredentialsError:
            current_app.logger.warning(f"No credentials available for AWS API")
            self._update_scan_status('credential_error')
            return []
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            current_app.logger.warning(f"Failed to fetch AWS regions due to AWS API error ({error_code}): {error_message}")
            self._update_scan_status('api_error')
            return []
        except Exception as e:
            current_app.logger.warning(f"Failed to fetch AWS regions: {str(e)}")
            self._update_scan_status('error')
            return []

    def _fetch_azure_regions(self, credentials: Dict[str, Any]) -> List[str]:
        """
        Fetch Azure regions using the Azure API.

        Args:
            credentials: Azure credentials dictionary

        Returns:
            List[str]: List of Azure region names
        """
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.resource import SubscriptionClient
            from azure.core.exceptions import ClientAuthenticationError, HttpResponseError

            credential = ClientSecretCredential(
                tenant_id=credentials.get('tenant_id'),
                client_id=credentials.get('client_id'),
                client_secret=credentials.get('client_secret')
            )

            subscription_id = credentials.get('subscription_id')
            subscription_client = SubscriptionClient(credential)

            locations = subscription_client.subscriptions.list_locations(subscription_id)

            # Update last scan time and status
            self.last_scan_time = datetime.utcnow()
            self.last_scan_status = 'success'
            db.session.commit()

            return [location.name for location in locations]
        except ImportError as e:
            current_app.logger.warning(f"Failed to fetch Azure regions due to missing dependencies: {str(e)}")
            self._update_scan_status('dependency_error')
            return []
        except ClientAuthenticationError as e:
            current_app.logger.warning(f"Authentication error while fetching Azure regions: {str(e)}")
            self._update_scan_status('auth_error')
            return []
        except HttpResponseError as e:
            current_app.logger.warning(f"HTTP error while fetching Azure regions: {str(e)}")
            self._update_scan_status('api_error')
            return []
        except (ValueError, KeyError) as e:
            current_app.logger.warning(f"Failed to fetch Azure regions due to invalid credentials: {str(e)}")
            self._update_scan_status('credential_error')
            return []
        except ConnectionError as e:
            current_app.logger.warning(f"Connection error while fetching Azure regions: {str(e)}")
            self._update_scan_status('connection_error')
            return []
        except Exception as e:
            current_app.logger.error(f"Unexpected error while fetching Azure regions: {str(e)}", exc_info=True)
            self._update_scan_status('error')
            return []

    def _fetch_gcp_regions(self, credentials: Dict[str, Any]) -> List[str]:
        """
        Fetch GCP regions using the GCP API.

        Args:
            credentials: GCP credentials dictionary

        Returns:
            List[str]: List of GCP region names
        """
        try:
            from google.oauth2 import service_account
            from google.cloud import compute_v1
            from google.api_core.exceptions import GoogleAPIError, PermissionDenied, Unauthenticated

            service_account_info = credentials.get('service_account_info')
            gcp_credentials = service_account.Credentials.from_service_account_info(service_account_info)

            client = compute_v1.RegionsClient(credentials=gcp_credentials)
            project_id = service_account_info.get('project_id')

            if not project_id:
                project_id = credentials.get('project_id')
                if not project_id:
                    raise ValueError("Missing project_id in credentials")

            request = compute_v1.ListRegionsRequest(project=project_id)
            regions = client.list(request=request)

            # Update last scan time and status
            self.last_scan_time = datetime.utcnow()
            self.last_scan_status = 'success'
            db.session.commit()

            return [region.name for region in regions]
        except ImportError as e:
            current_app.logger.warning(f"Failed to fetch GCP regions due to missing dependencies: {str(e)}")
            self._update_scan_status('dependency_error')
            return []
        except (KeyError, ValueError) as e:
            current_app.logger.warning(f"Failed to fetch GCP regions due to invalid credentials: {str(e)}")
            self._update_scan_status('credential_error')
            return []
        except PermissionDenied as e:
            current_app.logger.warning(f"Permission denied while fetching GCP regions: {str(e)}")
            self._update_scan_status('permission_error')
            return []
        except Unauthenticated as e:
            current_app.logger.warning(f"Authentication error while fetching GCP regions: {str(e)}")
            self._update_scan_status('auth_error')
            return []
        except GoogleAPIError as e:
            current_app.logger.warning(f"GCP API error while fetching regions: {str(e)}")
            self._update_scan_status('api_error')
            return []
        except Exception as e:
            current_app.logger.error(f"Unexpected error while fetching GCP regions: {str(e)}", exc_info=True)
            self._update_scan_status('error')
            return []

    def _update_scan_status(self, status: str) -> None:
        """
        Update the last scan time and status.

        Args:
            status: Status string to set
        """
        try:
            self.last_scan_time = datetime.utcnow()
            self.last_scan_status = status
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to update scan status: {str(e)}")

    def verify_connection(self) -> Dict[str, Any]:
        """
        Verify connection to the cloud provider.

        Returns:
            Dict with connection status and details
        """
        credentials = self.get_credentials_dict()
        if not credentials:
            return {
                'status': 'error',
                'message': 'No credentials available',
                'provider': self.name,
                'provider_type': self.provider_type,
                'timestamp': datetime.utcnow().isoformat()
            }

        validation_result = self._validate_credentials(credentials)

        # Add additional context to the result
        result = {
            'status': 'success' if validation_result['valid'] else 'error',
            'message': validation_result['message'],
            'provider': self.name,
            'provider_type': self.provider_type,
            'timestamp': datetime.utcnow().isoformat()
        }

        # Track verification attempt if metrics exist
        if hasattr(metrics, 'counter'):
            metrics.counter(
                'cloud_provider_verification_total',
                1,
                {
                    'provider_type': self.provider_type,
                    'provider_id': str(self.id),
                    'status': 'success' if validation_result['valid'] else 'error'
                }
            )

        return result

    @classmethod
    def clean_region_cache(cls, provider_id: Optional[int] = None) -> int:
        """
        Clean the region cache for one or all providers.

        Args:
            provider_id: Optional provider ID to clean cache for

        Returns:
            int: Number of cache keys cleaned
        """
        cleaned = 0

        try:
            if provider_id:
                cache_key = f'provider_regions:{provider_id}'
                if cache.delete(cache_key):
                    cleaned += 1
            else:
                providers = cls.query.all()
                for provider in providers:
                    cache_key = f'provider_regions:{provider.id}'
                    if cache.delete(cache_key):
                        cleaned += 1

            return cleaned
        except Exception as e:
            current_app.logger.error(f"Error cleaning region cache: {str(e)}")
            return 0

    def __repr__(self) -> str:
        """String representation of CloudProvider object."""
        return f"<CloudProvider id={self.id} name='{self.name}' type={self.provider_type}>"
