"""
Threat Intelligence model for the Cloud Infrastructure Platform.

This module provides data models for storing, managing, and analyzing threat
intelligence data, including indicators of compromise (IOCs) and threat feeds.
It supports integration with external threat intelligence sources and provides
capabilities for identifying and assessing security threats.

Features:
- Comprehensive indicator of compromise (IOC) management
- Threat feed integration and tracking
- Correlation between indicators and security events
- Risk scoring and threat assessment
- Historical threat data analysis
- Confidence-based evaluation of threat intelligence
"""

import json
import uuid
import ipaddress
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Union, Tuple, Set
from sqlalchemy import func, case, desc, and_, or_, not_, text
from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app, request, has_app_context

from extensions import db, cache, metrics
from models.base import BaseModel, AuditableMixin
from models.security.audit_log import AuditLog
from core.security.cs_audit import log_security_event
from core.security.cs_authentication import is_valid_ip, is_valid_domain, is_valid_hash


class ThreatIndicator(BaseModel, AuditableMixin):
    """
    Model representing an indicator of compromise (IOC) or threat indicator.

    This model stores information about potential security threats in the form
    of network indicators (IPs, domains), file indicators (hashes), or other
    threat intelligence data.

    Attributes:
        id: Primary key
        indicator_type: Type of indicator (ip, domain, hash, url, etc.)
        value: The indicator value (e.g., the IP address, domain, hash)
        source: Where this indicator came from (feed name, manual, etc.)
        description: Human-readable description of the threat
        severity: Criticality level (critical, high, medium, low)
        confidence: Confidence score from 0-100 for this indicator's accuracy
        tags: List of tags for categorization and filtering
        first_seen: When this indicator was first observed
        last_seen: When this indicator was most recently observed
        expiration: When this indicator should be considered outdated
        is_active: Whether this indicator should be used in threat detection
        context: Additional context for this indicator (campaigns, actors, etc.)
        matches: Count of times this indicator has been matched
        last_match: When this indicator was last matched
        metadata: Additional metadata about the indicator
    """

    __tablename__ = 'threat_indicators'

    # Indicator types
    TYPE_IP = 'ip'
    TYPE_DOMAIN = 'domain'
    TYPE_URL = 'url'
    TYPE_FILE_HASH = 'file_hash'
    TYPE_EMAIL = 'email'
    TYPE_USER_AGENT = 'user_agent'
    TYPE_FILENAME = 'filename'
    TYPE_REGISTRY = 'registry'
    TYPE_ASN = 'asn'
    TYPE_CIDR = 'cidr'
    TYPE_MUTEX = 'mutex'
    TYPE_PROCESS = 'process'
    TYPE_COMMAND = 'command'

    VALID_TYPES = [
        TYPE_IP, TYPE_DOMAIN, TYPE_URL, TYPE_FILE_HASH, TYPE_EMAIL,
        TYPE_USER_AGENT, TYPE_FILENAME, TYPE_REGISTRY, TYPE_ASN,
        TYPE_CIDR, TYPE_MUTEX, TYPE_PROCESS, TYPE_COMMAND
    ]

    # Severity levels
    SEVERITY_CRITICAL = 'critical'
    SEVERITY_HIGH = 'high'
    SEVERITY_MEDIUM = 'medium'
    SEVERITY_LOW = 'low'
    SEVERITY_INFO = 'info'

    VALID_SEVERITIES = [
        SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO
    ]

    # Source constants
    SOURCE_MANUAL = 'manual'
    SOURCE_FEED_AUTO = 'feed_auto'
    SOURCE_IMPORT = 'import'
    SOURCE_SYSTEM_DERIVED = 'system_derived'
    SOURCE_ANALYSIS = 'analysis'

    # Redis cache keys
    CACHE_PREFIX = 'threat:indicator:'
    CACHE_IP_SET = 'threat:ip_set'
    CACHE_DOMAIN_SET = 'threat:domain_set'
    CACHE_HASH_SET = 'threat:hash_set'
    CACHE_TTL = 86400  # 24 hours

    # Primary columns
    id = db.Column(db.Integer, primary_key=True)
    indicator_type = db.Column(db.String(20), nullable=False, index=True)
    value = db.Column(db.String(255), nullable=False, index=True)
    source = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(10), nullable=False, default=SEVERITY_MEDIUM)
    confidence = db.Column(db.Integer, nullable=False, default=50)  # 0-100 scale

    # Temporal information
    first_seen = db.Column(db.DateTime(timezone=True), nullable=True)
    last_seen = db.Column(db.DateTime(timezone=True), nullable=True)
    expiration = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                          onupdate=lambda: datetime.now(timezone.utc))

    # Status and metadata
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    context = db.Column(JSONB, nullable=True)
    matches = db.Column(db.Integer, default=0)
    last_match = db.Column(db.DateTime(timezone=True), nullable=True)
    metadata = db.Column(JSONB, nullable=True)

    # Tags (PostgreSQL specific array)
    tags = db.Column(JSONB, nullable=True)

    # Unique constraint
    __table_args__ = (
        db.UniqueConstraint('indicator_type', 'value', name='uix_indicator_type_value'),
    )

    def __init__(self, **kwargs):
        """Initialize a new threat indicator."""
        # Set default timestamps
        now = datetime.now(timezone.utc)
        kwargs.setdefault('created_at', now)
        kwargs.setdefault('updated_at', now)
        kwargs.setdefault('first_seen', now)
        kwargs.setdefault('last_seen', now)

        # Validate indicator type
        indicator_type = kwargs.get('indicator_type')
        if indicator_type and indicator_type not in self.VALID_TYPES:
            raise ValueError(f"Invalid indicator type: {indicator_type}")

        # Validate indicator value based on type
        indicator_type = kwargs.get('indicator_type')
        value = kwargs.get('value')
        if indicator_type and value:
            self._validate_indicator_value(indicator_type, value)

        # Ensure valid severity
        severity = kwargs.get('severity')
        if severity and severity not in self.VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        # Ensure confidence is within range
        confidence = kwargs.get('confidence')
        if confidence is not None:
            kwargs['confidence'] = max(0, min(100, confidence))

        # Ensure tags is a list
        tags = kwargs.get('tags')
        if tags is not None and not isinstance(tags, list):
            if isinstance(tags, str):
                kwargs['tags'] = [t.strip() for t in tags.split(',') if t.strip()]
            else:
                kwargs['tags'] = []

        # Initialize with validated kwargs
        super().__init__(**kwargs)

    def _validate_indicator_value(self, indicator_type: str, value: str) -> None:
        """
        Validate an indicator value based on its type.

        Args:
            indicator_type: The type of the indicator
            value: The indicator value to validate

        Raises:
            ValueError: If validation fails
        """
        if not value:
            raise ValueError("Indicator value cannot be empty")

        if indicator_type == self.TYPE_IP:
            if not is_valid_ip(value):
                raise ValueError(f"Invalid IP address format: {value}")

        elif indicator_type == self.TYPE_DOMAIN:
            if not is_valid_domain(value):
                raise ValueError(f"Invalid domain format: {value}")

        elif indicator_type == self.TYPE_URL:
            # Basic URL validation
            url_pattern = re.compile(
                r'^(?:http|https)://'  # http:// or https://
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain
                r'localhost|'  # localhost
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # or ipv4
                r'(?::\d+)?'  # optional port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            if not url_pattern.match(value):
                raise ValueError(f"Invalid URL format: {value}")

        elif indicator_type == self.TYPE_FILE_HASH:
            if not is_valid_hash(value):
                raise ValueError(f"Invalid hash format: {value}")

        elif indicator_type == self.TYPE_EMAIL:
            # Basic email validation
            email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
            if not email_pattern.match(value):
                raise ValueError(f"Invalid email format: {value}")

    def update(self, **kwargs) -> None:
        """
        Update threat indicator attributes.

        Args:
            **kwargs: Attributes to update
        """
        # Validate indicator type if provided
        if 'indicator_type' in kwargs and kwargs['indicator_type'] not in self.VALID_TYPES:
            raise ValueError(f"Invalid indicator type: {kwargs['indicator_type']}")

        # Validate value if type and value are both provided
        if 'indicator_type' in kwargs and 'value' in kwargs:
            self._validate_indicator_value(kwargs['indicator_type'], kwargs['value'])
        # If only value is changing, validate against existing type
        elif 'value' in kwargs:
            self._validate_indicator_value(self.indicator_type, kwargs['value'])

        # Validate severity if provided
        if 'severity' in kwargs and kwargs['severity'] not in self.VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {kwargs['severity']}")

        # Ensure confidence is within range if provided
        if 'confidence' in kwargs:
            kwargs['confidence'] = max(0, min(100, kwargs['confidence']))

        # Handle tags if provided
        if 'tags' in kwargs and not isinstance(kwargs['tags'], list):
            if isinstance(kwargs['tags'], str):
                kwargs['tags'] = [t.strip() for t in kwargs['tags'].split(',') if t.strip()]
            else:
                kwargs['tags'] = []

        # Update attributes
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

        # Update timestamp
        self.updated_at = datetime.now(timezone.utc)

    def record_match(self) -> None:
        """Record a match against this indicator."""
        self.matches += 1
        self.last_match = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert indicator to dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of indicator
        """
        return {
            'id': self.id,
            'indicator_type': self.indicator_type,
            'value': self.value,
            'source': self.source,
            'description': self.description,
            'severity': self.severity,
            'confidence': self.confidence,
            'tags': self.tags,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'expiration': self.expiration.isoformat() if self.expiration else None,
            'is_active': self.is_active,
            'context': self.context,
            'matches': self.matches,
            'last_match': self.last_match.isoformat() if self.last_match else None,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def serialize_for_cache(self) -> Dict[str, Any]:
        """
        Serialize indicator for caching.

        Returns:
            Dict[str, Any]: Simplified representation for cache
        """
        return {
            'id': self.id,
            'type': self.indicator_type,
            'value': self.value,
            'severity': self.severity,
            'confidence': self.confidence,
            'is_active': self.is_active
        }

    def save(self) -> bool:
        """
        Save the indicator to database and update cache.

        Returns:
            bool: Success status
        """
        try:
            db.session.add(self)
            db.session.commit()

            # Update cache
            self._update_cache()

            # Log an audit event
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_CONFIG_CHANGE,
                description=f"Threat indicator saved: {self.indicator_type} - {self.value}",
                severity="info",
                details=self.to_dict()
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error saving threat indicator: {e}")
            return False

    def delete(self) -> bool:
        """
        Delete the indicator from database and cache.

        Returns:
            bool: Success status
        """
        try:
            # Store values before deletion for cache and audit
            indicator_id = self.id
            indicator_type = self.indicator_type
            indicator_value = self.value
            indicator_dict = self.to_dict()

            # Delete from database
            db.session.delete(self)
            db.session.commit()

            # Remove from cache
            self._remove_from_cache(indicator_type, indicator_value)

            # Log an audit event
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_CONFIG_CHANGE,
                description=f"Threat indicator deleted: {indicator_type} - {indicator_value}",
                severity="info",
                details=indicator_dict
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error deleting threat indicator: {e}")
            return False

    def _update_cache(self) -> None:
        """Update Redis cache with this indicator."""
        if not self.is_active:
            self._remove_from_cache(self.indicator_type, self.value)
            return

        redis_client = self._get_redis_client()
        if not redis_client:
            return

        try:
            # Store serialized indicator
            key = f"{self.CACHE_PREFIX}{self.id}"
            redis_client.setex(
                key,
                self.CACHE_TTL,
                json.dumps(self.serialize_for_cache())
            )

            # Add to type-specific sets for faster lookups
            if self.indicator_type == self.TYPE_IP:
                redis_client.sadd(self.CACHE_IP_SET, self.value)
                redis_client.expire(self.CACHE_IP_SET, self.CACHE_TTL)
            elif self.indicator_type == self.TYPE_DOMAIN:
                redis_client.sadd(self.CACHE_DOMAIN_SET, self.value)
                redis_client.expire(self.CACHE_DOMAIN_SET, self.CACHE_TTL)
            elif self.indicator_type == self.TYPE_FILE_HASH:
                redis_client.sadd(self.CACHE_HASH_SET, self.value)
                redis_client.expire(self.CACHE_HASH_SET, self.CACHE_TTL)

        except Exception as e:
            if has_app_context() and current_app.logger:
                current_app.logger.warning(f"Error updating threat indicator cache: {e}")

    def _remove_from_cache(self, indicator_type: str, value: str) -> None:
        """
        Remove indicator from Redis cache.

        Args:
            indicator_type: Indicator type
            value: Indicator value
        """
        redis_client = self._get_redis_client()
        if not redis_client:
            return

        try:
            # Remove from type-specific sets
            if indicator_type == self.TYPE_IP:
                redis_client.srem(self.CACHE_IP_SET, value)
            elif indicator_type == self.TYPE_DOMAIN:
                redis_client.srem(self.CACHE_DOMAIN_SET, value)
            elif indicator_type == self.TYPE_FILE_HASH:
                redis_client.srem(self.CACHE_HASH_SET, value)

            # Remove serialized indicator
            key = f"{self.CACHE_PREFIX}{self.id}"
            redis_client.delete(key)

        except Exception as e:
            if has_app_context() and current_app.logger:
                current_app.logger.warning(f"Error removing threat indicator from cache: {e}")

    @classmethod
    def create(cls, **kwargs) -> 'ThreatIndicator':
        """
        Create a new threat indicator.

        Args:
            **kwargs: Indicator attributes

        Returns:
            ThreatIndicator: Created indicator
        """
        indicator = cls(**kwargs)
        return indicator

    @classmethod
    def find_by_id(cls, indicator_id: int) -> Optional['ThreatIndicator']:
        """
        Find an indicator by ID.

        Args:
            indicator_id: Indicator ID

        Returns:
            Optional[ThreatIndicator]: Found indicator or None
        """
        try:
            return cls.query.get(indicator_id)
        except SQLAlchemyError as e:
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error finding threat indicator by ID: {e}")
            return None

    @classmethod
    def find_by_value_and_type(cls, value: str, indicator_type: str) -> Optional['ThreatIndicator']:
        """
        Find an indicator by value and type.

        Args:
            value: Indicator value
            indicator_type: Indicator type

        Returns:
            Optional[ThreatIndicator]: Found indicator or None
        """
        try:
            return cls.query.filter(
                cls.value == value,
                cls.indicator_type == indicator_type
            ).first()
        except SQLAlchemyError as e:
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error finding threat indicator by value and type: {e}")
            return None

    @classmethod
    def get_active_indicators(cls, indicator_type: Optional[str] = None) -> List['ThreatIndicator']:
        """
        Get all active indicators, optionally filtered by type.

        Args:
            indicator_type: Optional indicator type filter

        Returns:
            List[ThreatIndicator]: List of active indicators
        """
        try:
            query = cls.query.filter(cls.is_active == True)

            if indicator_type:
                query = query.filter(cls.indicator_type == indicator_type)

            return query.order_by(cls.updated_at.desc()).all()
        except SQLAlchemyError as e:
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error getting active threat indicators: {e}")
            return []

    @classmethod
    def get_expiring_indicators(cls, days: int = 7) -> List['ThreatIndicator']:
        """
        Get indicators that will expire within specified days.

        Args:
            days: Number of days threshold

        Returns:
            List[ThreatIndicator]: List of expiring indicators
        """
        try:
            expiry_cutoff = datetime.now(timezone.utc) + timedelta(days=days)

            return cls.query.filter(
                cls.is_active == True,
                cls.expiration.isnot(None),
                cls.expiration <= expiry_cutoff
            ).all()
        except SQLAlchemyError as e:
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error getting expiring threat indicators: {e}")
            return []

    @classmethod
    def get_paginated(cls, page: int = 1, per_page: int = 20, sort_by: str = 'updated_at',
                     sort_direction: str = 'desc', filters: Optional[Dict[str, Any]] = None
                     ) -> Tuple[List['ThreatIndicator'], int]:
        """
        Get paginated list of indicators with optional filtering and sorting.

        Args:
            page: Page number (1-indexed)
            per_page: Items per page
            sort_by: Column to sort by
            sort_direction: Direction to sort (asc or desc)
            filters: Optional filters to apply

        Returns:
            Tuple[List[ThreatIndicator], int]: List of indicators and total count
        """
        try:
            query = cls.query

            # Apply filters if provided
            if filters:
                if 'indicator_type' in filters:
                    query = query.filter(cls.indicator_type == filters['indicator_type'])

                if 'source' in filters:
                    query = query.filter(cls.source == filters['source'])

                if 'severity' in filters:
                    if isinstance(filters['severity'], list):
                        query = query.filter(cls.severity.in_(filters['severity']))
                    else:
                        query = query.filter(cls.severity == filters['severity'])

                if 'is_active' in filters:
                    query = query.filter(cls.is_active == filters['is_active'])

                if 'confidence_min' in filters:
                    query = query.filter(cls.confidence >= filters['confidence_min'])

                if 'confidence_max' in filters:
                    query = query.filter(cls.confidence <= filters['confidence_max'])

                if 'tags' in filters and filters['tags']:
                    if db.engine.dialect.name == 'postgresql':
                        for tag in filters['tags']:
                            # Check if tag is in the JSONB array
                            query = query.filter(cls.tags.contains([tag]))
                    else:
                        # Fallback for other databases - less efficient
                        pass

                if 'search' in filters and filters['search']:
                    search_term = f"%{filters['search']}%"
                    query = query.filter(
                        or_(
                            cls.value.ilike(search_term),
                            cls.description.ilike(search_term)
                        )
                    )

            # Count total before applying pagination
            total = query.count()

            # Apply sorting
            if hasattr(cls, sort_by):
                column = getattr(cls, sort_by)
                if sort_direction.lower() == 'asc':
                    query = query.order_by(column.asc())
                else:
                    query = query.order_by(column.desc())

            # Apply pagination
            results = query.offset((page - 1) * per_page).limit(per_page).all()

            return results, total
        except SQLAlchemyError as e:
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error getting paginated threat indicators: {e}")
            return [], 0

    @classmethod
    def check_for_matches(cls, value: str, indicator_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Check if a value matches any known threat indicators.

        Args:
            value: The value to check
            indicator_type: Optional type hint for more accurate matching

        Returns:
            List[Dict[str, Any]]: List of matching indicators
        """
        if not value:
            return []

        # Try cache first for common types
        matches = cls._check_cache_for_matches(value, indicator_type)
        if matches:
            return matches

        # Fall back to database
        return cls._check_db_for_matches(value, indicator_type)

    @classmethod
    def _check_cache_for_matches(cls, value: str, indicator_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Check Redis cache for indicator matches.

        Args:
            value: Value to check
            indicator_type: Optional type hint

        Returns:
            List[Dict[str, Any]]: Matching indicators from cache
        """
        redis_client = cls._get_redis_client()
        if not redis_client:
            return []

        try:
            matches = []

            # If type is specified, only check that type
            if indicator_type:
                if indicator_type == cls.TYPE_IP and redis_client.sismember(cls.CACHE_IP_SET, value):
                    matches.append({'type': cls.TYPE_IP, 'value': value})
                elif indicator_type == cls.TYPE_DOMAIN and redis_client.sismember(cls.CACHE_DOMAIN_SET, value):
                    matches.append({'type': cls.TYPE_DOMAIN, 'value': value})
                elif indicator_type == cls.TYPE_FILE_HASH and redis_client.sismember(cls.CACHE_HASH_SET, value):
                    matches.append({'type': cls.TYPE_FILE_HASH, 'value': value})
            else:
                # Check against all types
                if redis_client.sismember(cls.CACHE_IP_SET, value):
                    matches.append({'type': cls.TYPE_IP, 'value': value})
                if redis_client.sismember(cls.CACHE_DOMAIN_SET, value):
                    matches.append({'type': cls.TYPE_DOMAIN, 'value': value})
                if redis_client.sismember(cls.CACHE_HASH_SET, value):
                    matches.append({'type': cls.TYPE_FILE_HASH, 'value': value})

            # If we found matches, fetch full details and record match
            if matches:
                detailed_matches = []

                for match in matches:
                    # Find the indicator in DB to get full details and record match
                    indicator = cls.find_by_value_and_type(match['value'], match['type'])
                    if indicator:
                        indicator.record_match()
                        indicator.save()
                        detailed_matches.append(indicator.to_dict())

                # Track metrics
                if detailed_matches and metrics:
                    metrics.info('threat_intelligence.indicators.matches', len(detailed_matches))

                return detailed_matches

            return []
        except Exception as e:
            if has_app_context() and current_app.logger:
                current_app.logger.warning(f"Error checking cache for threat indicator matches: {e}")
            return []

    @classmethod
    def _check_db_for_matches(cls, value: str, indicator_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Check database for indicator matches.

        Args:
            value: Value to check
            indicator_type: Optional type hint

        Returns:
            List[Dict[str, Any]]: Matching indicators from database
        """
        try:
            # Start with a basic query for active indicators
            query = cls.query.filter(cls.is_active == True)

            # If specific type is provided, filter by it
            if indicator_type:
                query = query.filter(cls.indicator_type == indicator_type)

                # Add exact match condition for the specified type
                query = query.filter(cls.value == value)
            else:
                # Try to match across different indicator types
                query = query.filter(cls.value == value)

            # Get matching indicators
            indicators = query.all()

            # Update match counts and last match time
            for indicator in indicators:
                indicator.record_match()
                indicator.save()

            # Track metrics
            if indicators and metrics:
                metrics.info('threat_intelligence.indicators.matches', len(indicators))

            # Convert to dictionaries
            return [indicator.to_dict() for indicator in indicators]
        except SQLAlchemyError as e:
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error checking database for threat indicator matches: {e}")
            return []

    @classmethod
    def bulk_import(cls, indicators: List[Dict[str, Any]]) -> Tuple[int, int, List[str]]:
        """
        Bulk import threat indicators.

        Args:
            indicators: List of indicator dictionaries

        Returns:
            Tuple[int, int, List[str]]: Count of imported, failed, and list of errors
        """
        imported = 0
        failed = 0
        errors = []

        for indicator_data in indicators:
            try:
                # Check if indicator already exists
                existing = cls.find_by_value_and_type(
                    indicator_data.get('value'),
                    indicator_data.get('indicator_type')
                )

                if existing:
                    # Update existing indicator
                    existing.update(**indicator_data)
                    if existing.save():
                        imported += 1
                    else:
                        failed += 1
                        errors.append(f"Failed to update {indicator_data.get('indicator_type')}:{indicator_data.get('value')}")
                else:
                    # Create new indicator
                    indicator = cls.create(**indicator_data)
                    if indicator.save():
                        imported += 1
                    else:
                        failed += 1
                        errors.append(f"Failed to create {indicator_data.get('indicator_type')}:{indicator_data.get('value')}")

            except Exception as e:
                failed += 1
                error_msg = f"Error processing {indicator_data.get('value', 'unknown')}: {str(e)}"
                errors.append(error_msg)
                if has_app_context() and current_app.logger:
                    current_app.logger.error(error_msg)

        # Log bulk import results
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_CONFIG_CHANGE,
            description=f"Bulk import of threat indicators: {imported} imported, {failed} failed",
            severity="info",
            details={
                "imported": imported,
                "failed": failed,
                "errors": errors[:10]  # Limit the number of errors in the log
            }
        )

        # Update cache for all active indicators
        cls.refresh_cache()

        return imported, failed, errors

    @classmethod
    def refresh_cache(cls) -> bool:
        """
        Refresh the Redis cache with all active indicators.

        Returns:
            bool: Success status
        """
        redis_client = cls._get_redis_client()
        if not redis_client:
            return False

        try:
            # Clear existing sets
            redis_client.delete(cls.CACHE_IP_SET)
            redis_client.delete(cls.CACHE_DOMAIN_SET)
            redis_client.delete(cls.CACHE_HASH_SET)

            # Get all active indicators and reindex
            active_indicators = cls.query.filter(cls.is_active == True).all()

            # Use a pipeline for better performance
            pipe = redis_client.pipeline()

            for indicator in active_indicators:
                # Store serialized indicator
                key = f"{cls.CACHE_PREFIX}{indicator.id}"
                pipe.setex(
                    key,
                    cls.CACHE_TTL,
                    json.dumps(indicator.serialize_for_cache())
                )

                # Add to type-specific sets
                if indicator.indicator_type == cls.TYPE_IP:
                    pipe.sadd(cls.CACHE_IP_SET, indicator.value)
                elif indicator.indicator_type == cls.TYPE_DOMAIN:
                    pipe.sadd(cls.CACHE_DOMAIN_SET, indicator.value)
                elif indicator.indicator_type == cls.TYPE_FILE_HASH:
                    pipe.sadd(cls.CACHE_HASH_SET, indicator.value)

            # Set expiry on sets
            pipe.expire(cls.CACHE_IP_SET, cls.CACHE_TTL)
            pipe.expire(cls.CACHE_DOMAIN_SET, cls.CACHE_TTL)
            pipe.expire(cls.CACHE_HASH_SET, cls.CACHE_TTL)

            # Execute all commands in the pipeline
            pipe.execute()

            return True
        except Exception as e:
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error refreshing threat indicator cache: {e}")
            return False

    @classmethod
    def get_stats(cls) -> Dict[str, Any]:
        """
        Get statistics about threat indicators.

        Returns:
            Dict[str, Any]: Statistics about indicators
        """
        try:
            stats = {
                'total_count': 0,
                'active_count': 0,
                'by_type': {},
                'by_severity': {},
                'by_confidence': {
                    'high': 0,
                    'medium': 0,
                    'low': 0
                },
                'recently_matched': 0,
                'recently_added': 0,
                'expiring_soon': 0
            }

            # Get total and active counts
            stats['total_count'] = cls.query.count()
            stats['active_count'] = cls.query.filter(cls.is_active == True).count()

            # Count by type
            type_counts = db.session.query(
                cls.indicator_type, func.count(cls.id)
            ).group_by(cls.indicator_type).all()

            for type_name, count in type_counts:
                stats['by_type'][type_name] = count

            # Count by severity
            severity_counts = db.session.query(
                cls.severity, func.count(cls.id)
            ).group_by(cls.severity).all()

            for severity, count in severity_counts:
                stats['by_severity'][severity] = count

            # Count by confidence
            stats['by_confidence']['high'] = cls.query.filter(cls.confidence >= 80).count()
            stats['by_confidence']['medium'] = cls.query.filter(
                cls.confidence >= 50, cls.confidence < 80
            ).count()
            stats['by_confidence']['low'] = cls.query.filter(cls.confidence < 50).count()

            # Recently matched (last 24 hours)
            day_ago = datetime.now(timezone.utc) - timedelta(days=1)
            stats['recently_matched'] = cls.query.filter(cls.last_match >= day_ago).count()

            # Recently added
            stats['recently_added'] = cls.query.filter(cls.created_at >= day_ago).count()

            # Expiring in next 7 days
            week_later = datetime.now(timezone.utc) + timedelta(days=7)
            stats['expiring_soon'] = cls.query.filter(
                cls.expiration.isnot(None),
                cls.expiration <= week_later,
                cls.expiration > datetime.now(timezone.utc),
                cls.is_active == True
            ).count()

            return stats

        except SQLAlchemyError as e:
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error getting threat indicator stats: {e}")
            return {
                'error': str(e),
                'total_count': 0
            }

    @classmethod
    def clear_expired(cls) -> int:
        """
        Clear expired indicators by marking them inactive.

        Returns:
            int: Number of indicators deactivated
        """
        try:
            now = datetime.now(timezone.utc)

            # Find expired indicators
            expired = cls.query.filter(
                cls.expiration.isnot(None),
                cls.expiration <= now,
                cls.is_active == True
            ).all()

            # Deactivate expired indicators
            for indicator in expired:
                indicator.is_active = False
                indicator.save()

            # Log the cleanup
            if expired:
                log_security_event(
                    event_type=AuditLog.EVENT_SECURITY_CONFIG_CHANGE,
                    description=f"Deactivated {len(expired)} expired threat indicators",
                    severity="info"
                )

                # Update cache
                cls.refresh_cache()

            return len(expired)

        except SQLAlchemyError as e:
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error clearing expired indicators: {e}")
            return 0

    @classmethod
    def _get_redis_client(cls):
        """Get Redis client from cache."""
        try:
            if cache and hasattr(cache, 'cache'):
                return cache.cache._client
        except Exception:
            pass
        return None


class ThreatFeed(BaseModel):
    """
    Model for external threat intelligence feeds.

    This model defines configuration for ingesting threat data from external
    sources and maintains metadata about each feed's operational status.

    Attributes:
        id: Primary key
        name: Feed name
        url: URL for feed data retrieval
        api_key: Optional API key for authentication
        feed_type: Type of feed (ip_list, domain_list, structured, etc.)
        description: Description of the feed
        enabled: Whether the feed is active
        last_update: When the feed was last updated
        last_update_status: Status of the last update
        update_interval: Update frequency in seconds
        credentials: Optional credentials configuration
        headers: Optional request headers
        transform_script: Optional transformation script
        config: Additional configuration
    """

    __tablename__ = 'threat_feeds'

    # Feed types
    TYPE_IP_LIST = 'ip_list'
    TYPE_DOMAIN_LIST = 'domain_list'
    TYPE_URL_LIST = 'url_list'
    TYPE_HASH_LIST = 'hash_list'
    TYPE_STRUCTURED_JSON = 'structured_json'
    TYPE_STRUCTURED_XML = 'structured_xml'
    TYPE_STIX = 'stix'
    TYPE_CUSTOM = 'custom'

    VALID_TYPES = [
        TYPE_IP_LIST, TYPE_DOMAIN_LIST, TYPE_URL_LIST, TYPE_HASH_LIST,
        TYPE_STRUCTURED_JSON, TYPE_STRUCTURED_XML, TYPE_STIX, TYPE_CUSTOM
    ]

    # Update status
    STATUS_SUCCESS = 'success'
    STATUS_FAILURE = 'failure'
    STATUS_PENDING = 'pending'
    STATUS_NEVER_RUN = 'never_run'

    # Primary columns
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    url = db.Column(db.String(512), nullable=False)
    api_key = db.Column(db.String(255), nullable=True)
    feed_type = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=True)
    enabled = db.Column(db.Boolean, default=True)

    # Update tracking
    last_update = db.Column(db.DateTime(timezone=True), nullable=True)
    last_update_status = db.Column(db.String(20), default=STATUS_NEVER_RUN)
    update_interval = db.Column(db.Integer, default=86400)  # Seconds (default: daily)

    # Configuration
    credentials = db.Column(JSONB, nullable=True)
    headers = db.Column(JSONB, nullable=True)
    transform_script = db.Column(db.Text, nullable=True)
    config = db.Column(JSONB, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                          onupdate=lambda: datetime.now(timezone.utc))

    def __init__(self, **kwargs):
        """Initialize a new threat feed."""
        # Validate feed type
        feed_type = kwargs.get('feed_type')
        if feed_type and feed_type not in self.VALID_TYPES:
            raise ValueError(f"Invalid feed type: {feed_type}")

        super().__init__(**kwargs)

    def update(self, **kwargs) -> None:
        """
        Update threat feed attributes.

        Args:
            **kwargs: Attributes to update
        """
        # Validate feed type if provided
        if 'feed_type' in kwargs and kwargs['feed_type'] not in self.VALID_TYPES:
            raise ValueError(f"Invalid feed type: {kwargs['feed_type']}")

        # Update attributes
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

        # Update timestamp
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert feed to dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of feed
        """
        return {
            'id': self.id,
            'name': self.name,
            'url': self.url,
            'feed_type': self.feed_type,
            'description': self.description,
            'enabled': self.enabled,
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'last_update_status': self.last_update_status,
            'update_interval': self.update_interval,
            'config': self.config,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def save(self) -> bool:
        """
        Save the feed to database.

        Returns:
            bool: Success status
        """
        try:
            db.session.add(self)
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error saving threat feed: {e}")
            return False

    def delete(self) -> bool:
        """
        Delete the feed from database.

        Returns:
            bool: Success status
        """
        try:
            # Store values before deletion for audit
            feed_id = self.id
            feed_name = self.name

            # Delete from database
            db.session.delete(self)
            db.session.commit()

            # Log an audit event
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_CONFIG_CHANGE,
                description=f"Threat feed deleted: {feed_name}",
                severity="info",
                details={"id": feed_id, "name": feed_name}
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error deleting threat feed: {e}")
            return False

    def should_update(self) -> bool:
        """
        Check if the feed should be updated.

        Returns:
            bool: True if the feed should be updated
        """
        if not self.enabled:
            return False

        if self.last_update is None:
            return True

        now = datetime.now(timezone.utc)
        time_since_update = (now - self.last_update).total_seconds()
        return time_since_update >= self.update_interval

    def update_status(self, status: str, indicators_added: int = 0, indicators_updated: int = 0, errors: List[str] = None) -> None:
        """
        Update feed status after an update operation.

        Args:
            status: Update status (success or failure)
            indicators_added: Number of indicators added
            indicators_updated: Number of indicators updated
            errors: List of error messages
        """
        self.last_update_status = status
        self.last_update = datetime.now(timezone.utc)

        # Create or update status metadata
        if not self.config:
            self.config = {}

        self.config.update({
            'last_update_stats': {
                'indicators_added': indicators_added,
                'indicators_updated': indicators_updated,
                'error_count': len(errors) if errors else 0,
                'errors': errors[:10] if errors else []  # Store first 10 errors
            }
        })

        # Save the updated status
        self.save()

        # Log an audit event
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_CONFIG_CHANGE,
            description=f"Threat feed '{self.name}' updated with status: {status}",
            severity="info" if status == self.STATUS_SUCCESS else "warning",
            details={
                "feed_id": self.id,
                "feed_name": self.name,
                "status": status,
                "indicators_added": indicators_added,
                "indicators_updated": indicators_updated,
                "errors": errors[:5] if errors else []  # Log first 5 errors
            }
        )

    @classmethod
    def create(cls, **kwargs) -> 'ThreatFeed':
        """
        Create a new threat feed.

        Args:
            **kwargs: Feed attributes

        Returns:
            ThreatFeed: Created feed
        """
        feed = cls(**kwargs)
        return feed

    @classmethod
    def find_by_id(cls, feed_id: int) -> Optional['ThreatFeed']:
        """
        Find a feed by ID.

        Args:
            feed_id: Feed ID

        Returns:
            Optional[ThreatFeed]: Found feed or None
        """
        try:
            return cls.query.get(feed_id)
        except SQLAlchemyError as e:
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error finding threat feed by ID: {e}")
            return None

    @classmethod
    def find_by_name(cls, name: str) -> Optional['ThreatFeed']:
        """
        Find a feed by name.

        Args:
            name: Feed name

        Returns:
            Optional[ThreatFeed]: Found feed or None
        """
        try:
            return cls.query.filter(cls.name == name).first()
        except SQLAlchemyError as e:
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error finding threat feed by name: {e}")
            return None

    @classmethod
    def get_feeds_needing_update(cls) -> List['ThreatFeed']:
        """
        Get feeds that need updating.

        Returns:
            List[ThreatFeed]: List of feeds needing update
        """
        try:
            now = datetime.now(timezone.utc)

            # Get all enabled feeds
            feeds = cls.query.filter(cls.enabled == True).all()

            # Filter to feeds that need to be updated
            needs_update = []
            for feed in feeds:
                if feed.should_update():
                    needs_update.append(feed)

            return needs_update
        except SQLAlchemyError as e:
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error getting threat feeds needing update: {e}")
            return []


class ThreatEvent(BaseModel):
    """
    Model for tracking threat detection events.

    This model records instances when a threat indicator is matched against
    system data, providing an audit trail of threat detections.

    Attributes:
        id: Primary key
        event_type: Type of threat event
        indicator_id: Optional reference to the matched indicator
        indicator_type: Type of indicator that was matched
        indicator_value: Value of the matched indicator
        severity: Event severity
        source: Source of the event (app, system, etc.)
        context: Contextual information about the match
        user_id: User ID associated with the event (if applicable)
        ip_address: IP address associated with the event
        action_taken: Action taken in response to the threat
    """

    __tablename__ = 'threat_events'

    # Event types
    TYPE_INDICATOR_MATCH = 'indicator_match'
    TYPE_SIGNATURE_MATCH = 'signature_match'
    TYPE_ANOMALY = 'anomaly'
    TYPE_BEHAVIOR = 'behavior'
    TYPE_MANUAL = 'manual'

    VALID_TYPES = [
        TYPE_INDICATOR_MATCH, TYPE_SIGNATURE_MATCH, TYPE_ANOMALY,
        TYPE_BEHAVIOR, TYPE_MANUAL
    ]

    # Action types
    ACTION_LOGGED = 'logged'
    ACTION_BLOCKED = 'blocked'
    ACTION_ALERTED = 'alerted'
    ACTION_QUARANTINED = 'quarantined'

    # Primary columns
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(20), nullable=False, index=True)
    indicator_id = db.Column(db.Integer, db.ForeignKey('threat_indicators.id', ondelete='SET NULL'), nullable=True)
    indicator_type = db.Column(db.String(20), nullable=True)
    indicator_value = db.Column(db.String(255), nullable=True)
    severity = db.Column(db.String(10), nullable=False, default=ThreatIndicator.SEVERITY_MEDIUM)
    source = db.Column(db.String(50), nullable=True)
    context = db.Column(JSONB, nullable=True)

    # Association fields
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)

    # Response tracking
    action_taken = db.Column(db.String(20), nullable=True, default=ACTION_LOGGED)
    incident_created = db.Column(db.Boolean, default=False)
    incident_id = db.Column(db.Integer, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    indicator = db.relationship('ThreatIndicator', backref='events')

    def __init__(self, **kwargs):
        """Initialize a new threat event."""
        # Validate event type
        event_type = kwargs.get('event_type')
        if event_type and event_type not in self.VALID_TYPES:
            raise ValueError(f"Invalid event type: {event_type}")

        # Validate severity
        severity = kwargs.get('severity')
        if severity and severity not in ThreatIndicator.VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        super().__init__(**kwargs)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert event to dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of event
        """
        return {
            'id': self.id,
            'event_type': self.event_type,
            'indicator_id': self.indicator_id,
            'indicator_type': self.indicator_type,
            'indicator_value': self.indicator_value,
            'severity': self.severity,
            'source': self.source,
            'context': self.context,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'action_taken': self.action_taken,
            'incident_created': self.incident_created,
            'incident_id': self.incident_id,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def save(self) -> bool:
        """
        Save the event to database.

        Returns:
            bool: Success status
        """
        try:
            db.session.add(self)
            db.session.commit()

            # Track metrics
            if metrics:
                metrics.info('threat_intelligence.events.detected', 1, {
                    'type': self.event_type,
                    'severity': self.severity
                })

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error saving threat event: {e}")
            return False

    def link_to_incident(self, incident_id: int) -> bool:
        """
        Link this event to a security incident.

        Args:
            incident_id: ID of the security incident

        Returns:
            bool: Success status
        """
        try:
            self.incident_created = True
            self.incident_id = incident_id
            return self.save()
        except Exception as e:
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error linking threat event to incident: {e}")
            return False

    @classmethod
    def create(cls, **kwargs) -> 'ThreatEvent':
        """
        Create a new threat event.

        Args:
            **kwargs: Event attributes

        Returns:
            ThreatEvent: Created event
        """
        event = cls(**kwargs)

        # Log security event
        log_security_event(
            event_type=AuditLog.EVENT_THREAT_DETECTION,
            description=f"Threat detected: {kwargs.get('indicator_type', 'unknown')}:{kwargs.get('indicator_value', 'unknown')}",
            severity=kwargs.get('severity', 'medium'),
            user_id=kwargs.get('user_id'),
            ip_address=kwargs.get('ip_address'),
            details={
                'indicator_type': kwargs.get('indicator_type'),
                'indicator_value': kwargs.get('indicator_value'),
                'action_taken': kwargs.get('action_taken', cls.ACTION_LOGGED)
            }
        )

        return event

    @classmethod
    def create_from_indicator_match(cls, indicator: ThreatIndicator, context: Dict[str, Any] = None,
                                   user_id: Optional[int] = None, ip_address: Optional[str] = None,
                                   action: str = None) -> 'ThreatEvent':
        """
        Create a threat event from an indicator match.

        Args:
            indicator: The matched indicator
            context: Contextual information about the match
            user_id: User ID associated with the event
            ip_address: IP address associated with the event
            action: Action taken in response to the threat

        Returns:
            ThreatEvent: Created event
        """
        event = cls(
            event_type=cls.TYPE_INDICATOR_MATCH,
            indicator_id=indicator.id,
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.value,
            severity=indicator.severity,
            source='indicator_database',
            context=context,
            user_id=user_id,
            ip_address=ip_address,
            action_taken=action or cls.ACTION_LOGGED
        )

        event.save()
        return event

    @classmethod
    def get_paginated(cls, page: int = 1, per_page: int = 20, filters: Optional[Dict[str, Any]] = None
                     ) -> Tuple[List['ThreatEvent'], int]:
        """
        Get paginated list of events with optional filtering.

        Args:
            page: Page number (1-indexed)
            per_page: Items per page
            filters: Optional filters to apply

        Returns:
            Tuple[List[ThreatEvent], int]: List of events and total count
        """
        try:
            query = cls.query

            # Apply filters if provided
            if filters:
                if 'event_type' in filters:
                    query = query.filter(cls.event_type == filters['event_type'])

                if 'indicator_type' in filters:
                    query = query.filter(cls.indicator_type == filters['indicator_type'])

                if 'severity' in filters:
                    if isinstance(filters['severity'], list):
                        query = query.filter(cls.severity.in_(filters['severity']))
                    else:
                        query = query.filter(cls.severity == filters['severity'])

                if 'start_date' in filters:
                    query = query.filter(cls.created_at >= filters['start_date'])

                if 'end_date' in filters:
                    query = query.filter(cls.created_at <= filters['end_date'])

                if 'user_id' in filters:
                    query = query.filter(cls.user_id == filters['user_id'])

                if 'ip_address' in filters:
                    query = query.filter(cls.ip_address == filters['ip_address'])

                if 'action_taken' in filters:
                    query = query.filter(cls.action_taken == filters['action_taken'])

                if 'indicator_value' in filters:
                    query = query.filter(cls.indicator_value.ilike(f"%{filters['indicator_value']}%"))

            # Count total before applying pagination
            total = query.count()

            # Apply sorting and pagination
            results = query.order_by(cls.created_at.desc()) \
                          .offset((page - 1) * per_page) \
                          .limit(per_page) \
                          .all()

            return results, total
        except SQLAlchemyError as e:
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error getting paginated threat events: {e}")
            return [], 0

    @classmethod
    def get_recent(cls, hours: int = 24, limit: int = 10) -> List['ThreatEvent']:
        """
        Get recent threat events.

        Args:
            hours: Number of hours to look back
            limit: Maximum number of events to return

        Returns:
            List[ThreatEvent]: List of recent events
        """
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

            return cls.query.filter(cls.created_at >= cutoff) \
                         .order_by(cls.created_at.desc()) \
                         .limit(limit) \
                         .all()
        except SQLAlchemyError as e:
            if has_app_context() and current_app.logger:
                current_app.logger.error(f"Error getting recent threat events: {e}")
            return []
