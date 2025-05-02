"""
Multi-Factor Authentication implementation for the API authentication module.

This module provides functionality for managing multi-factor authentication methods
including TOTP, and backup codes. It supports MFA enrollment, verification,
and management with proper security controls and audit logging.
"""

import logging
import os
import base64
import pyotp
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple, List, Union
from flask import current_app, jsonify, request, g
from sqlalchemy.exc import SQLAlchemyError

from extensions import db, limiter, metrics
from models.auth import MFAMethod, MFAVerification
from core.security import log_security_event, is_mfa_verified, mark_mfa_verified
from core.security.cs_authentication import generate_secure_token
from . import auth_api


logger = logging.getLogger(__name__)


@auth_api.route('/mfa/setup', methods=['POST'])
@limiter.limit("3/hour")
def setup_mfa() -> Tuple[Dict[str, Any], int]:
    """
    Set up a new MFA method for the current user.

    This endpoint initiates MFA setup by generating and returning necessary
    credentials (e.g., TOTP secret, or QR code URI).
    The setup is completed using the verify endpoint.

    Request body:
        type (str): Type of MFA method to set up (totp, backup_codes)
        name (str, optional): User-friendly name for the device/method

    Returns:
        JSON response with setup details appropriate for the MFA type
    """
    user_id = g.user.id if hasattr(g, 'user') and g.user else None
    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    # Parse request body
    data = request.get_json() or {}
    mfa_type = data.get('type', 'totp').lower()
    name = data.get('name', 'Primary')

    # Track metrics
    metrics.increment('auth.mfa_setup_initiated', 1, labels={'method': mfa_type})

    # Validate MFA type
    if mfa_type not in MFAMethod.VALID_TYPES:
        return jsonify({
            "error": "Invalid MFA method type",
            "valid_types": MFAMethod.VALID_TYPES
        }), 400

    try:
        # Check for existing methods of this type
        existing_method = MFAMethod.query.filter_by(
            user_id=user_id,
            method_type=mfa_type,
            is_active=True
        ).first()

        # If method exists and is already verified, return error
        if existing_method and existing_method.verified:
            return jsonify({
                "error": f"MFA method of type '{mfa_type}' is already set up",
                "method_id": existing_method.id
            }), 409

        # If method exists but is not verified, we can reuse it
        if existing_method and not existing_method.verified:
            mfa_method = existing_method
        else:
            # Create new MFA method
            mfa_method = MFAMethod(
                user_id=user_id,
                method_type=mfa_type,
                name=name,
                is_active=True,
                verified=False
            )
            db.session.add(mfa_method)
            db.session.commit()

        # Generate appropriate setup data based on type
        if mfa_type == MFAMethod.TYPE_TOTP:
            setup_data = _setup_totp(mfa_method)
        elif mfa_type == MFAMethod.TYPE_BACKUP_CODES:
            setup_data = _setup_backup_codes(mfa_method)
        else:
            # For other methods like SMS/Email
            setup_data = {"method_id": mfa_method.id}

        # Add setup token for verification step
        setup_token = generate_secure_token()
        setup_data['setup_token'] = setup_token
        setup_data['method_id'] = mfa_method.id

        # Store the setup token in the session for verification
        if hasattr(g, 'session_manager'):
            g.session_manager.set('mfa_setup_token', setup_token, ttl=1800)  # 30 minutes
            g.session_manager.set('mfa_setup_method_id', mfa_method.id, ttl=1800)

        # Log setup initiation
        log_security_event(
            event_type='mfa_setup_initiated',
            description=f"MFA setup initiated: {mfa_type}",
            user_id=user_id,
            severity='info',
            ip_address=request.remote_addr,
            details={"method_type": mfa_type, "method_id": mfa_method.id}
        )

        return jsonify(setup_data), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error in MFA setup: {str(e)}")
        metrics.increment('auth.mfa_setup_error', 1, labels={'error': 'database'})
        return jsonify({"error": "Database error during MFA setup"}), 500

    except Exception as e:
        logger.error(f"Error in MFA setup: {str(e)}", exc_info=True)
        metrics.increment('auth.mfa_setup_error', 1, labels={'error': 'general'})
        return jsonify({"error": "Failed to set up MFA"}), 500


@auth_api.route('/mfa/verify', methods=['POST'])
@limiter.limit("10/minute")
def verify_mfa_setup() -> Tuple[Dict[str, Any], int]:
    """
    Verify and complete MFA setup process.

    This endpoint verifies the provided MFA credentials (verification code, fingerprint, etc.)
    to complete the MFA setup process.

    Request body:
        method_id (int): ID of the MFA method to verify
        setup_token (str): Setup token from the setup step
        code (str): Verification code for TOTP/backup codes

    Returns:
        JSON with verification result and status
    """
    user_id = g.user.id if hasattr(g, 'user') and g.user else None
    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    # Parse request body
    data = request.get_json() or {}
    method_id = data.get('method_id')
    setup_token = data.get('setup_token')
    verification_code = data.get('code')

    # Basic validation
    if not method_id or not setup_token:
        return jsonify({"error": "Missing required parameters"}), 400

    # Validate setup token
    stored_token = None
    if hasattr(g, 'session_manager'):
        stored_token = g.session_manager.get('mfa_setup_token')
        stored_method_id = g.session_manager.get('mfa_setup_method_id')

        if not stored_token or not stored_method_id or stored_token != setup_token or int(stored_method_id) != int(method_id):
            metrics.increment('auth.mfa_verification_error', 1, labels={'error': 'invalid_token'})
            return jsonify({"error": "Invalid or expired setup token"}), 401

    try:
        # Get the MFA method
        mfa_method = MFAMethod.query.filter_by(
            id=method_id,
            user_id=user_id,
            is_active=True
        ).first()

        if not mfa_method:
            return jsonify({"error": "MFA method not found"}), 404

        # Handle verification based on method type
        verified = False
        verification_type = ''

        if mfa_method.method_type == MFAMethod.TYPE_TOTP:
            if not verification_code:
                return jsonify({"error": "Verification code required"}), 400

            verified = _verify_totp(mfa_method, verification_code)
            verification_type = 'totp'

        elif mfa_method.method_type == MFAMethod.TYPE_BACKUP_CODES:
            if not verification_code:
                return jsonify({"error": "Verification code required"}), 400

            verified = _verify_backup_code(mfa_method, verification_code)
            verification_type = 'backup_code'

        if verified:
            # Mark method as verified
            mfa_method.verified = True

            # If this is the first verified method for the user, make it primary
            if not MFAMethod.query.filter(
                MFAMethod.user_id == user_id,
                MFAMethod.is_active == True,
                MFAMethod.verified == True,
                MFAMethod.id != mfa_method.id
            ).count():
                mfa_method.is_primary = True

            db.session.commit()

            # Clear setup tokens
            if hasattr(g, 'session_manager'):
                g.session_manager.delete('mfa_setup_token')
                g.session_manager.delete('mfa_setup_method_id')

            # Log successful verification
            log_security_event(
                event_type='mfa_setup_completed',
                description=f"MFA setup completed: {mfa_method.method_type}",
                user_id=user_id,
                severity='info',
                ip_address=request.remote_addr,
                details={"method_type": mfa_method.method_type, "method_id": mfa_method.id}
            )

            # Track metrics
            metrics.increment('auth.mfa_setup_completed', 1, labels={'method': mfa_method.method_type})

            # Generate backup codes if necessary
            backup_codes = None
            if mfa_method.method_type != MFAMethod.TYPE_BACKUP_CODES:
                # Check for existing backup codes
                backup_method = MFAMethod.query.filter_by(
                    user_id=user_id,
                    method_type=MFAMethod.TYPE_BACKUP_CODES,
                    is_active=True
                ).first()

                # Create backup codes if they don't exist
                if not backup_method:
                    backup_method = MFAMethod(
                        user_id=user_id,
                        method_type=MFAMethod.TYPE_BACKUP_CODES,
                        name="Backup Codes",
                        is_active=True
                    )
                    db.session.add(backup_method)
                    db.session.commit()

                # Generate codes if needed
                if not backup_method.verified:
                    backup_codes = backup_method.generate_backup_codes()

            return jsonify({
                "success": True,
                "message": "MFA setup completed successfully",
                "mfa_enabled": True,
                "method_id": mfa_method.id,
                "method_type": mfa_method.method_type,
                "backup_codes": backup_codes
            }), 200
        else:
            # Log failed verification
            MFAVerification.log_verification(
                user_id=user_id,
                verification_type=verification_type,
                success=False,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                session_id=request.cookies.get('session', None),
                mfa_method_id=mfa_method.id
            )

            # Track metrics
            metrics.increment('auth.mfa_setup_verification_failed', 1, labels={'method': mfa_method.method_type})

            return jsonify({
                "success": False,
                "error": "Invalid verification code",
                "message": "Failed to verify MFA setup"
            }), 401

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error in MFA verification: {str(e)}")
        metrics.increment('auth.mfa_verification_error', 1, labels={'error': 'database'})
        return jsonify({"error": "Database error during MFA verification"}), 500

    except Exception as e:
        logger.error(f"Error in MFA verification: {str(e)}", exc_info=True)
        metrics.increment('auth.mfa_verification_error', 1, labels={'error': 'general'})
        return jsonify({"error": "Failed to verify MFA setup"}), 500


@auth_api.route('/mfa/methods', methods=['GET'])
@limiter.limit("30/minute")
def list_mfa_methods() -> Tuple[Dict[str, Any], int]:
    """
    List MFA methods configured for the current user.

    Returns a list of the user's configured MFA methods with metadata.
    Sensitive information like secrets is never included.

    Returns:
        JSON array of MFA methods
    """
    user_id = g.user.id if hasattr(g, 'user') and g.user else None
    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    try:
        # Get MFA methods for the user
        methods = MFAMethod.query.filter_by(
            user_id=user_id,
            is_active=True
        ).all()

        result = []
        for method in methods:
            result.append({
                "id": method.id,
                "type": method.method_type,
                "name": method.name,
                "is_primary": method.is_primary,
                "verified": method.verified,
                "created_at": method.created_at.isoformat() if method.created_at else None,
                "last_used_at": method.last_used_at.isoformat() if method.last_used_at else None
            })

        return jsonify({
            "methods": result,
            "mfa_enabled": bool(result) and any(m["verified"] for m in result)
        }), 200

    except Exception as e:
        logger.error(f"Error listing MFA methods: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to retrieve MFA methods"}), 500


@auth_api.route('/mfa/methods/<int:method_id>', methods=['DELETE'])
@limiter.limit("10/hour")
def delete_mfa_method(method_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Delete an MFA method.

    Removes the specified MFA method if it belongs to the current user.
    At least one MFA method must remain if MFA is required for the user's role.

    Args:
        method_id: ID of the MFA method to delete

    Returns:
        JSON with deletion result
    """
    user_id = g.user.id if hasattr(g, 'user') and g.user else None
    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    try:
        # Get the method to be deleted
        mfa_method = MFAMethod.query.filter_by(
            id=method_id,
            user_id=user_id
        ).first()

        if not mfa_method:
            return jsonify({"error": "MFA method not found"}), 404

        # Check if this is the only verified method and if MFA is required
        active_methods = MFAMethod.query.filter(
            MFAMethod.user_id == user_id,
            MFAMethod.is_active == True,
            MFAMethod.verified == True
        ).count()

        mfa_required = False
        if hasattr(g, 'user') and g.user:
            roles = [g.user.role]
            mfa_required_roles = current_app.config.get('MFA_REQUIRED_ROLES', [])
            mfa_required = any(role in mfa_required_roles for role in roles)

        if mfa_required and active_methods <= 1:
            return jsonify({
                "error": "Cannot delete last MFA method",
                "message": "MFA is required for your role. Add another method before removing this one."
            }), 403

        # Store method type for logging
        method_type = mfa_method.method_type

        # Soft delete by deactivating
        mfa_method.is_active = False

        # If this was primary, make another method primary if available
        if mfa_method.is_primary:
            next_method = MFAMethod.query.filter(
                MFAMethod.user_id == user_id,
                MFAMethod.is_active == True,
                MFAMethod.verified == True,
                MFAMethod.id != method_id
            ).first()

            if next_method:
                next_method.is_primary = True

        db.session.commit()

        # Log the removal
        log_security_event(
            event_type='mfa_method_removed',
            description=f"MFA method removed: {method_type}",
            user_id=user_id,
            severity='warning',
            ip_address=request.remote_addr,
            details={"method_type": method_type, "method_id": method_id}
        )

        # Track metrics
        metrics.increment('auth.mfa_method_removed', 1, labels={'method': method_type})

        return jsonify({
            "success": True,
            "message": "MFA method removed successfully"
        }), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error removing MFA method: {str(e)}")
        return jsonify({"error": "Database error during MFA method removal"}), 500

    except Exception as e:
        logger.error(f"Error removing MFA method: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to remove MFA method"}), 500


@auth_api.route('/mfa/challenge', methods=['POST'])
@limiter.limit("20/minute")
def mfa_challenge() -> Tuple[Dict[str, Any], int]:
    """
    Request MFA challenge for verification.

    This endpoint returns a challenge that the client can use to prove
    possession of the MFA credential.

    Request body:
        method_id (int, optional): ID of the MFA method to challenge,
                                  if not provided, primary method is used

    Returns:
        JSON with challenge data
    """
    user_id = g.user.id if hasattr(g, 'user') and g.user else None
    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json() or {}
    method_id = data.get('method_id')

    try:
        # Get the specified method or the primary method
        if method_id:
            mfa_method = MFAMethod.query.filter_by(
                id=method_id,
                user_id=user_id,
                is_active=True,
                verified=True
            ).first()
        else:
            # Get primary method
            mfa_method = MFAMethod.query.filter_by(
                user_id=user_id,
                is_active=True,
                verified=True,
                is_primary=True
            ).first()

            # If no primary method, get any verified method
            if not mfa_method:
                mfa_method = MFAMethod.query.filter_by(
                    user_id=user_id,
                    is_active=True,
                    verified=True
                ).first()

        if not mfa_method:
            return jsonify({
                "error": "No MFA method available",
                "message": "You need to set up MFA before verification"
            }), 404

        # Generate challenge based on method type
        challenge = {}
        method_type = mfa_method.method_type
        challenge_token = generate_secure_token()

        # Create challenge for appropriate method type
        if method_type == MFAMethod.TYPE_TOTP:
            challenge = {
                "type": "totp",
                "challenge_token": challenge_token
            }
        elif method_type == MFAMethod.TYPE_BACKUP_CODES:
            challenge = {
                "type": "backup_code",
                "challenge_token": challenge_token
            }

        # Store challenge token with method id
        if hasattr(g, 'session_manager'):
            g.session_manager.set('mfa_challenge_token', challenge_token, ttl=300)  # 5 minutes
            g.session_manager.set('mfa_challenge_method_id', mfa_method.id, ttl=300)

        challenge['method_id'] = mfa_method.method_id
        challenge['method_name'] = mfa_method.name

        # Log challenge generation
        log_security_event(
            event_type='mfa_challenge_generated',
            description=f"MFA challenge generated: {method_type}",
            user_id=user_id,
            severity='info',
            ip_address=request.remote_addr,
            details={"method_type": method_type, "method_id": mfa_method.id}
        )

        return jsonify({
            "challenge": challenge,
            "expires_in": 300  # 5 minutes
        }), 200

    except Exception as e:
        logger.error(f"Error generating MFA challenge: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to generate MFA challenge"}), 500


@auth_api.route('/mfa/verify', methods=['POST'])
@limiter.limit("10/minute")
def verify_mfa() -> Tuple[Dict[str, Any], int]:
    """
    Verify a MFA challenge response.

    This endpoint verifies the provided MFA credentials against a previously
    issued challenge and updates the session to reflect MFA verification.

    Request body:
        method_id (int): ID of the MFA method
        challenge_token (str): Challenge token from the challenge step
        code (str): Verification code for TOTP/backup codes

    Returns:
        JSON with verification result
    """
    user_id = g.user.id if hasattr(g, 'user') and g.user else None
    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    # Parse request body
    data = request.get_json() or {}
    method_id = data.get('method_id')
    challenge_token = data.get('challenge_token')
    verification_code = data.get('code')

    # Basic validation
    if not method_id or not challenge_token:
        return jsonify({"error": "Missing required parameters"}), 400

    # Validate challenge token
    stored_token = None
    if hasattr(g, 'session_manager'):
        stored_token = g.session_manager.get('mfa_challenge_token')
        stored_method_id = g.session_manager.get('mfa_challenge_method_id')

        if not stored_token or not stored_method_id or stored_token != challenge_token or int(stored_method_id) != int(method_id):
            metrics.increment('auth.mfa_verification_error', 1, labels={'error': 'invalid_token'})
            return jsonify({"error": "Invalid or expired challenge token"}), 401

    try:
        # Get the MFA method
        mfa_method = MFAMethod.query.filter_by(
            id=method_id,
            user_id=user_id,
            is_active=True,
            verified=True
        ).first()

        if not mfa_method:
            return jsonify({"error": "MFA method not found"}), 404

        # Handle verification based on method type
        verified = False
        verification_type = ''

        if mfa_method.method_type == MFAMethod.TYPE_TOTP:
            if not verification_code:
                return jsonify({"error": "Verification code required"}), 400

            verified = _verify_totp(mfa_method, verification_code)
            verification_type = 'totp'

        elif mfa_method.method_type == MFAMethod.TYPE_BACKUP_CODES:
            if not verification_code:
                return jsonify({"error": "Verification code required"}), 400

            verified = _verify_backup_code(mfa_method, verification_code)
            verification_type = 'backup_code'

        # Log verification attempt
        MFAVerification.log_verification(
            user_id=user_id,
            verification_type=verification_type,
            success=verified,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            session_id=request.cookies.get('session', None),
            mfa_method_id=mfa_method.id
        )

        # Clear challenge tokens
        if hasattr(g, 'session_manager'):
            g.session_manager.delete('mfa_challenge_token')
            g.session_manager.delete('mfa_challenge_method_id')

        if verified:
            # Mark session as MFA verified
            mark_mfa_verified()

            # Track metrics
            metrics.increment('auth.mfa_verification_success', 1, labels={'method': mfa_method.method_type})

            # Log successful verification
            log_security_event(
                event_type='mfa_verified',
                description=f"MFA verified: {mfa_method.method_type}",
                user_id=user_id,
                severity='info',
                ip_address=request.remote_addr,
                details={"method_type": mfa_method.method_type, "method_id": mfa_method.id}
            )

            return jsonify({
                "success": True,
                "message": "MFA verification successful",
                "mfa_verified": True
            }), 200
        else:
            # Track metrics
            metrics.increment('auth.mfa_verification_failed', 1, labels={'method': mfa_method.method_type})

            # Check for too many failed attempts
            recent_failures = MFAVerification.get_recent_failures(user_id)

            return jsonify({
                "success": False,
                "error": "Invalid verification code",
                "message": "MFA verification failed",
                "attempts_remaining": max(0, 5 - recent_failures)  # Allow 5 attempts
            }), 401

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error in MFA verification: {str(e)}")
        metrics.increment('auth.mfa_verification_error', 1, labels={'error': 'database'})
        return jsonify({"error": "Database error during MFA verification"}), 500

    except Exception as e:
        logger.error(f"Error in MFA verification: {str(e)}", exc_info=True)
        metrics.increment('auth.mfa_verification_error', 1, labels={'error': 'general'})
        return jsonify({"error": "Failed to verify MFA"}), 500


@auth_api.route('/mfa/backup-codes', methods=['POST'])
@limiter.limit("3/hour")
def generate_backup_codes() -> Tuple[Dict[str, Any], int]:
    """
    Generate new backup codes for the user.

    This endpoint creates a set of new backup codes that can be used for MFA.
    Any existing backup codes are invalidated.

    Request body:
        verification_code (str): Current MFA code for verification

    Returns:
        JSON array of backup codes
    """
    user_id = g.user.id if hasattr(g, 'user') and g.user else None
    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    # Require MFA verification for this sensitive operation
    if not is_mfa_verified():
        # Use X-MFA-Token if provided
        mfa_token = request.headers.get('X-MFA-Token')
        data = request.get_json() or {}
        verification_code = data.get('verification_code', mfa_token)

        if not verification_code:
            return jsonify({
                "error": "MFA verification required",
                "code": "MFA_REQUIRED",
                "message": "Verify your identity with MFA before generating backup codes"
            }), 403

        # Find primary MFA method
        primary_method = MFAMethod.query.filter_by(
            user_id=user_id,
            is_primary=True,
            is_active=True,
            verified=True
        ).first()

        if not primary_method:
            # Find any verified non-backup code method
            primary_method = MFAMethod.query.filter(
                MFAMethod.user_id == user_id,
                MFAMethod.is_active == True,
                MFAMethod.verified == True,
                MFAMethod.method_type != MFAMethod.TYPE_BACKUP_CODES
            ).first()

        if not primary_method:
            return jsonify({
                "error": "No MFA method available for verification",
                "message": "You need to set up MFA before generating backup codes"
            }), 404

        # Verify the code
        verified = False
        if primary_method.method_type == MFAMethod.TYPE_TOTP:
            verified = _verify_totp(primary_method, verification_code)

        if not verified:
            metrics.increment('auth.backup_codes_verification_failed')
            return jsonify({
                "error": "Invalid verification code",
                "message": "MFA verification failed"
            }), 401

        # Mark as MFA verified if successful
        mark_mfa_verified()

    try:
        # Find or create backup codes method
        backup_method = MFAMethod.query.filter_by(
            user_id=user_id,
            method_type=MFAMethod.TYPE_BACKUP_CODES,
            is_active=True
        ).first()

        if not backup_method:
            backup_method = MFAMethod(
                user_id=user_id,
                method_type=MFAMethod.TYPE_BACKUP_CODES,
                name="Backup Codes",
                is_active=True
            )
            db.session.add(backup_method)
            db.session.commit()

        # Generate new backup codes
        backup_codes = backup_method.generate_backup_codes()

        # Log backup code generation
        log_security_event(
            event_type='backup_codes_generated',
            description="New backup codes generated",
            user_id=user_id,
            severity='warning',
            ip_address=request.remote_addr
        )

        # Track metrics
        metrics.increment('auth.backup_codes_generated')

        return jsonify({
            "backup_codes": backup_codes,
            "count": len(backup_codes),
            "message": "New backup codes generated successfully"
        }), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error generating backup codes: {str(e)}")
        return jsonify({"error": "Database error during backup code generation"}), 500

    except Exception as e:
        logger.error(f"Error generating backup codes: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to generate backup codes"}), 500


# Helper Functions

def _setup_totp(mfa_method: MFAMethod) -> Dict[str, str]:
    """
    Set up TOTP authentication.

    Args:
        mfa_method: MFA method object to configure

    Returns:
        Dict with setup data
    """
    # Get issuer from config
    issuer = current_app.config.get('MFA_TOTP_ISSUER', 'Cloud Platform')

    # Setup TOTP
    setup_data = mfa_method.setup_totp(
        name=mfa_method.name,
        issuer=issuer
    )

    # Generate QR code data URL using utils function
    from core.utils.qr import generate_qr_data_url
    try:
        qr_code = generate_qr_data_url(setup_data['uri'])
        setup_data['qr_code'] = qr_code
    except ImportError:
        # Fall back to URI if QR generation is not available
        setup_data['qr_code'] = None

    return setup_data


def _setup_backup_codes(mfa_method: MFAMethod) -> Dict[str, Any]:
    """
    Set up backup codes.

    Args:
        mfa_method: MFA method object to configure

    Returns:
        Dict with setup data
    """
    # Get number of backup codes from config
    count = current_app.config.get('MFA_BACKUP_CODE_COUNT', 10)

    # Generate backup codes
    codes = mfa_method.generate_backup_codes(count)

    return {
        "backup_codes": codes,
        "count": len(codes)
    }


def _verify_totp(mfa_method: MFAMethod, code: str) -> bool:
    """
    Verify a TOTP code.

    Args:
        mfa_method: MFA method to verify against
        code: TOTP code from authenticator app

    Returns:
        bool: True if verified, False otherwise
    """
    # Strip whitespace and normalize
    normalized_code = code.strip().replace(' ', '')

    # Call method's verify function
    return mfa_method.verify_totp(normalized_code)


def _verify_backup_code(mfa_method: MFAMethod, code: str) -> bool:
    """
    Verify a backup code.

    Args:
        mfa_method: MFA method to verify against
        code: Backup code from user

    Returns:
        bool: True if verified, False otherwise
    """
    # Strip whitespace and normalize
    normalized_code = code.strip().replace(' ', '').replace('-', '')

    # Call method's verify function
    return mfa_method.verify_backup_code(normalized_code)
