"""
Permission context rules model for the Cloud Infrastructure Platform.

This module provides flexible context-based rules for permission evaluation,
supporting attribute-based access control (ABAC) on top of role-based access control.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple, Union, Set
from flask import current_app, g
import json
from jsonpath_ng import parse as parse_jsonpath
from sqlalchemy.exc import SQLAlchemyError

from extensions import db
from models.base import BaseModel, AuditableMixin

class PermissionContextRule(BaseModel, AuditableMixin):
    """
    Model for storing attribute-based permission context rules.

    These rules enhance basic RBAC permissions with contextual attributes
    to implement attribute-based access control (ABAC).
    """

    __tablename__ = 'permission_context_rules'

    # Security critical fields that trigger enhanced auditing
    SECURITY_CRITICAL_FIELDS = ['rule_definition', 'is_active']

    # Rule types
    TYPE_ALLOW = 'allow'  # Rule grants access if matched
    TYPE_DENY = 'deny'    # Rule denies access if matched

    id = db.Column(db.Integer, primary_key=True)
    permission_id = db.Column(db.Integer, db.ForeignKey('permissions.id', ondelete='CASCADE'),
                           nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)

    # Rule definition in JSON format
    # Example: {"resource_owner_id": {"$eq": "${user.id}"}}
    # Special variables: ${user.id}, ${user.roles}, etc.
    rule_definition = db.Column(db.JSON, nullable=False)

    rule_type = db.Column(db.String(20), default=TYPE_ALLOW, nullable=False)
    evaluation_order = db.Column(db.Integer, default=100, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                         onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    permission = db.relationship('Permission', backref=db.backref('context_rules', lazy='dynamic',
                                                               cascade='all, delete-orphan'))

    def __init__(self, permission_id: int, name: str, rule_definition: Dict[str, Any],
                rule_type: str = TYPE_ALLOW, evaluation_order: int = 100,
                description: Optional[str] = None):
        """
        Initialize a new permission context rule.

        Args:
            permission_id: ID of the permission this rule applies to
            name: Name of the rule for identification
            rule_definition: JSON definition of the rule
            rule_type: 'allow' or 'deny'
            evaluation_order: Order of rule evaluation (lower numbers evaluated first)
            description: Optional description of the rule
        """
        self.permission_id = permission_id
        self.name = name
        self.rule_definition = rule_definition
        self.rule_type = rule_type if rule_type in [self.TYPE_ALLOW, self.TYPE_DENY] else self.TYPE_ALLOW
        self.evaluation_order = evaluation_order
        self.description = description

    def evaluate(self, context: Dict[str, Any], user_data: Dict[str, Any]) -> Optional[bool]:
        """
        Evaluate this rule against the provided context and user data.

        Args:
            context: Request context attributes
            user_data: User attributes for variable substitution

        Returns:
            Optional[bool]: True if rule allows, False if rule denies, None if rule doesn't apply
        """
        try:
            # Skip inactive rules
            if not self.is_active:
                return None

            # Process the rule definition with variable substitution
            processed_rule = self._process_variables(self.rule_definition, user_data)

            # Check if the rule matches the context
            if self._matches_context(processed_rule, context):
                return self.rule_type == self.TYPE_ALLOW

            # Rule doesn't apply to this context
            return None

        except Exception as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error evaluating permission rule {self.id}: {str(e)}")
            # On error, skip this rule
            return None

    def _process_variables(self, rule_part: Any, user_data: Dict[str, Any]) -> Any:
        """Replace variables in the rule with actual values."""
        if isinstance(rule_part, str) and rule_part.startswith('${') and rule_part.endswith('}'):
            # Extract the variable path
            var_path = rule_part[2:-1].strip()  # Remove ${ and }

            # Handle special variables
            if var_path == 'user.id':
                return user_data.get('id')
            elif var_path == 'user.role_ids':
                return user_data.get('role_ids', [])
            elif var_path.startswith('user.'):
                # Use dot notation to navigate user_data
                parts = var_path.split('.')[1:]
                value = user_data
                for part in parts:
                    if isinstance(value, dict) and part in value:
                        value = value[part]
                    else:
                        return None
                return value

            # Unknown variable
            return None

        elif isinstance(rule_part, dict):
            return {k: self._process_variables(v, user_data) for k, v in rule_part.items()}

        elif isinstance(rule_part, list):
            return [self._process_variables(item, user_data) for item in rule_part]

        # Return other types unchanged
        return rule_part

    def _matches_context(self, rule: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Check if the rule matches the context."""
        for key, condition in rule.items():
            # Skip metadata keys that start with _
            if key.startswith('_'):
                continue

            # Handle special condition operators
            if isinstance(condition, dict) and len(condition) == 1:
                operator, value = next(iter(condition.items()))

                if operator == "$eq":
                    # Equality comparison
                    if key not in context or context[key] != value:
                        return False
                elif operator == "$ne":
                    # Not equal comparison
                    if key in context and context[key] == value:
                        return False
                elif operator == "$in":
                    # Check if context value is in the list
                    if key not in context or context[key] not in value:
                        return False
                elif operator == "$nin":
                    # Check if context value is not in the list
                    if key in context and context[key] in value:
                        return False
                elif operator == "$gt":
                    # Greater than comparison
                    if key not in context or not (context[key] > value):
                        return False
                elif operator == "$gte":
                    # Greater than or equal comparison
                    if key not in context or not (context[key] >= value):
                        return False
                elif operator == "$lt":
                    # Less than comparison
                    if key not in context or not (context[key] < value):
                        return False
                elif operator == "$lte":
                    # Less than or equal comparison
                    if key not in context or not (context[key] <= value):
                        return False
                elif operator == "$exists":
                    # Check if field exists
                    if bool(value) != (key in context):
                        return False
                elif operator == "$regex":
                    # TODO: Implement regex matching if needed
                    pass

            # Direct value comparison
            elif key in context:
                if context[key] != condition:
                    return False
            else:
                # Key doesn't exist in context
                return False

        # All conditions matched
        return True

    @classmethod
    def get_rules_for_permission(cls, permission_id: int) -> List['PermissionContextRule']:
        """Get all active rules for a permission, ordered by evaluation_order."""
        return cls.query.filter_by(
            permission_id=permission_id,
            is_active=True
        ).order_by(cls.evaluation_order).all()

    @classmethod
    def evaluate_permission(cls, permission_id: int, context: Dict[str, Any],
                          user_data: Dict[str, Any]) -> bool:
        """
        Evaluate all rules for a permission to determine access.

        Args:
            permission_id: ID of the permission to check
            context: Request context attributes
            user_data: User data for variable substitution

        Returns:
            bool: True if access is granted, False otherwise
        """
        # Get all rules for this permission
        rules = cls.get_rules_for_permission(permission_id)

        if not rules:
            # No rules defined, default to basic RBAC result (which is assumed to be true
            # if this function is being called)
            return True

        # Start with default deny
        result = None

        # Evaluate rules in order
        for rule in rules:
            rule_result = rule.evaluate(context, user_data)
            if rule_result is not None:
                result = rule_result
                # If this is a deny rule that matched, we can stop evaluation
                if not result:
                    break

        # If no rules matched, use default allow since we assume user has the base permission
        return True if result is None else result

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'permission_id': self.permission_id,
            'name': self.name,
            'description': self.description,
            'rule_definition': self.rule_definition,
            'rule_type': self.rule_type,
            'evaluation_order': self.evaluation_order,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
