"""
SMS Service for the Cloud Infrastructure Platform.

This service centralizes SMS messaging functionality, providing consistent
error handling, delivery tracking, and rate limiting. It integrates with
the notification system and respects user communication preferences.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union, Tuple

from flask import current_app, has_app_context
from extensions import db, metrics, cache

# Import user preference models if available
try:
    from models.communication.user_preference import NotificationPreference, CommunicationPreference
    USER_PREFERENCES_AVAILABLE = True
except ImportError:
    USER_PREFERENCES_AVAILABLE = False

# Import service constants if available
try:
    from services.service_constants import (
        NOTIFICATION_CATEGORY_SYSTEM,
        NOTIFICATION_CATEGORY_SECURITY,
        NOTIFICATION_CATEGORY_USER,
        NOTIFICATION_CATEGORY_ADMIN,
        NOTIFICATION_CATEGORY_MAINTENANCE,
        NOTIFICATION_CATEGORY_MONITORING,
        NOTIFICATION_CATEGORY_COMPLIANCE,
        NOTIFICATION_CATEGORY_INTEGRITY,
        NOTIFICATION_CATEGORY_AUDIT,
        NOTIFICATION_CATEGORY_SCAN,
        NOTIFICATION_CATEGORY_VULNERABILITY,
        NOTIFICATION_CATEGORY_INCIDENT,
        # SMS-specific constants
        SMS_DEFAULT_REGION,
        SMS_MAX_LENGTH,
        SMS_RETRY_COUNT,
        SMS_CRITICAL_PRIORITY,
        SMS_HIGH_PRIORITY,
        SMS_MEDIUM_PRIORITY,
        SMS_LOW_PRIORITY,
        SMS_RATE_LIMIT_WINDOW,
        SMS_RATE_LIMIT_MAX_PER_USER,
        SMS_ALLOWED_DOMAINS
    )
    SERVICE_CONSTANTS_AVAILABLE = True
except ImportError:
    # Default values if service_constants not available
    SERVICE_CONSTANTS_AVAILABLE = False
    NOTIFICATION_CATEGORY_SYSTEM = 'system'
    NOTIFICATION_CATEGORY_SECURITY = 'security'
    NOTIFICATION_CATEGORY_USER = 'user'
    NOTIFICATION_CATEGORY_ADMIN = 'admin'
    NOTIFICATION_CATEGORY_MAINTENANCE = 'maintenance'
    NOTIFICATION_CATEGORY_MONITORING = 'monitoring'
    NOTIFICATION_CATEGORY_COMPLIANCE = 'compliance'
    NOTIFICATION_CATEGORY_INTEGRITY = 'integrity'
    NOTIFICATION_CATEGORY_AUDIT = 'audit'
    NOTIFICATION_CATEGORY_SCAN = 'scan'
    NOTIFICATION_CATEGORY_VULNERABILITY = 'vulnerability'
    NOTIFICATION_CATEGORY_INCIDENT = 'incident'

    # SMS-specific default constants
    SMS_DEFAULT_REGION = 'US'
    SMS_MAX_LENGTH = 160
    SMS_RETRY_COUNT = 3
    SMS_CRITICAL_PRIORITY = 'critical'
    SMS_HIGH_PRIORITY = 'high'
    SMS_MEDIUM_PRIORITY = 'medium'
    SMS_LOW_PRIORITY = 'low'
    SMS_RATE_LIMIT_WINDOW = 300  # 5 minutes
    SMS_RATE_LIMIT_MAX_PER_USER = 5  # 5 messages per window
    SMS_ALLOWED_DOMAINS = []

# Configure logging
logger = logging.getLogger(__name__)

# SMS provider enumeration
class SMSProvider:
    """Enum of supported SMS providers"""
    TWILIO = 'twilio'
    AWS_SNS = 'aws_sns'
    MESSAGEBIRD = 'messagebird'
    VONAGE = 'vonage'
    MOCK = 'mock'  # For testing

class SMSService:
    """
    Provides methods for sending and managing SMS messages.
    """

    @staticmethod
    def send_sms(
        to: str,
        message: str,
        priority: str = SMS_MEDIUM_PRIORITY,
        tracking_id: Optional[str] = None,
        category: Optional[str] = None,
        sender_id: Optional[str] = None,
        provider: Optional[str] = None,
        retry_count: int = SMS_RETRY_COUNT
    ) -> Dict[str, Any]:
        """
        Send an SMS message with tracking and delivery status.

        Args:
            to: Recipient phone number in E.164 format (+12345678901)
            message: Message content
            priority: Priority level (default: medium)
            tracking_id: Optional ID for tracking this message
            category: Notification category for routing/tracking
            sender_id: Optional sender ID or alphanumeric sender
            provider: SMS provider to use (default: system default)
            retry_count: Number of delivery attempts

        Returns:
            Dictionary with delivery status and details
        """
        if not to or not message:
            logger.warning("Missing required parameters for SMS: recipient or message")
            return {
                'success': False,
                'error': 'Missing required parameters',
                'tracking_id': tracking_id or str(uuid.uuid4())
            }

        # Generate tracking ID if not provided
        if not tracking_id:
            tracking_id = f"sms-{uuid.uuid4().hex[:12]}"

        # Truncate message if too long
        if len(message) > SMS_MAX_LENGTH:
            original_length = len(message)
            message = message[:SMS_MAX_LENGTH - 3] + "..."
            logger.debug(f"Message truncated from {original_length} to {len(message)} characters")

        # Get current provider from config if not specified
        if not provider and has_app_context():
            provider = current_app.config.get('SMS_PROVIDER', SMSProvider.TWILIO)
        elif not provider:
            provider = SMSProvider.TWILIO  # Default

        # Get sender ID from config if not specified
        if not sender_id and has_app_context():
            sender_id = current_app.config.get('SMS_SENDER_ID')

        # Check rate limits
        if has_app_context() and hasattr(current_app, 'config'):
            if not SMSService._check_rate_limit(to):
                logger.warning(f"Rate limit exceeded for recipient: {to}")
                metrics.increment('sms.rate_limited')
                return {
                    'success': False,
                    'error': 'Rate limit exceeded',
                    'tracking_id': tracking_id
                }

        # Check if SMS is configured
        if not SMSService._is_sms_configured(provider):
            logger.warning(f"SMS provider {provider} not configured")
            return {
                'success': False,
                'error': f'SMS provider {provider} not configured',
                'tracking_id': tracking_id
            }

        # Log attempt
        SMSService._log_sms_attempt(tracking_id, to, message, priority, category)

        # Call provider-specific sending function
        try:
            result = SMSService._send_with_provider(
                provider=provider,
                to=to,
                message=message,
                sender_id=sender_id,
                tracking_id=tracking_id,
                priority=priority,
                retry_count=retry_count,
                category=category
            )

            # Update metrics based on result
            if result.get('success', False):
                metrics.increment(f'sms.sent.{priority}')
                metrics.increment(f'sms.success')
            else:
                metrics.increment(f'sms.failed.{priority}')
                logger.error(f"Failed to send SMS: {result.get('error')}")

            # Track by category if available
            if category:
                if result.get('success', False):
                    metrics.increment(f'sms.category.{category}.success')
                else:
                    metrics.increment(f'sms.category.{category}.failed')

            return result

        except Exception as e:
            logger.error(f"Unexpected error sending SMS: {str(e)}")
            metrics.increment('sms.error')
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}',
                'tracking_id': tracking_id
            }

    @staticmethod
    def send_bulk_sms(
        recipients: List[str],
        message: str,
        priority: str = SMS_MEDIUM_PRIORITY,
        category: Optional[str] = None,
        respect_preferences: bool = True
    ) -> Dict[str, Any]:
        """
        Send SMS messages to multiple recipients.

        Args:
            recipients: List of phone numbers
            message: Message content
            priority: Priority level
            category: Notification category
            respect_preferences: Whether to respect user communication preferences

        Returns:
            Dictionary with delivery statistics
        """
        if not recipients:
            logger.warning("No recipients provided for bulk SMS")
            return {
                'success': False,
                'error': 'No recipients provided',
                'stats': {
                    'total': 0,
                    'sent': 0,
                    'failed': 0
                }
            }

        # Generate tracking ID for bulk operation
        bulk_tracking_id = f"bulk-sms-{uuid.uuid4().hex[:12]}"

        # Filter recipients by preferences if enabled
        if respect_preferences and USER_PREFERENCES_AVAILABLE:
            recipients = SMSService._filter_by_preferences(recipients, category, priority)

        # Initialize counters
        sent_count = 0
        failed_count = 0
        failures = []

        # Send to each recipient
        for recipient in recipients:
            result = SMSService.send_sms(
                to=recipient,
                message=message,
                priority=priority,
                category=category,
                tracking_id=f"{bulk_tracking_id}-{sent_count + failed_count + 1}"
            )

            if result.get('success', False):
                sent_count += 1
            else:
                failed_count += 1
                failures.append({
                    'recipient': recipient,
                    'error': result.get('error', 'Unknown error')
                })

        # Log statistics
        logger.info(f"Bulk SMS completed: {sent_count}/{len(recipients)} sent successfully")
        metrics.increment('sms.bulk.operations')
        metrics.gauge('sms.bulk.sent', sent_count)
        metrics.gauge('sms.bulk.failed', failed_count)

        return {
            'success': sent_count > 0,
            'tracking_id': bulk_tracking_id,
            'stats': {
                'total': len(recipients),
                'sent': sent_count,
                'failed': failed_count
            },
            'failures': failures if failures else None
        }

    @staticmethod
    def verify_phone_number(phone_number: str) -> Dict[str, Any]:
        """
        Verify a phone number's validity and format.

        Args:
            phone_number: Phone number to verify

        Returns:
            Dictionary with verification results
        """
        if not phone_number:
            return {
                'valid': False,
                'error': 'Phone number cannot be empty',
                'formatted': None
            }

        try:
            # Try to use the phonenumbers library if available
            try:
                import phonenumbers
                parsed = phonenumbers.parse(phone_number, SMS_DEFAULT_REGION)

                if not phonenumbers.is_valid_number(parsed):
                    return {
                        'valid': False,
                        'error': 'Invalid phone number',
                        'formatted': None
                    }

                # Format in E.164 format
                formatted = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)

                return {
                    'valid': True,
                    'formatted': formatted,
                    'country_code': parsed.country_code,
                    'national_number': parsed.national_number
                }
            except ImportError:
                logger.debug("phonenumbers library not available, using basic validation")

                # Basic validation as fallback
                phone_number = phone_number.strip()
                if not phone_number.startswith('+'):
                    phone_number = f"+{phone_number}"

                # Remove any spaces, dashes or parentheses
                cleaned = ''.join(c for c in phone_number if c.isdigit() or c == '+')

                # Basic format check
                if not (cleaned.startswith('+') and len(cleaned) >= 9 and len(cleaned) <= 16):
                    return {
                        'valid': False,
                        'error': 'Phone number does not match E.164 format',
                        'formatted': None
                    }

                return {
                    'valid': True,
                    'formatted': cleaned
                }

        except Exception as e:
            logger.error(f"Error validating phone number: {str(e)}")
            return {
                'valid': False,
                'error': f'Validation error: {str(e)}',
                'formatted': None
            }

    @staticmethod
    def get_delivery_status(message_id: str) -> Dict[str, Any]:
        """
        Get the current delivery status of an SMS message.

        Args:
            message_id: ID of the message to check

        Returns:
            Dictionary with status information
        """
        try:
            # Get provider from message store or default
            provider = SMSService._get_provider_for_message(message_id)

            if not provider:
                return {
                    'found': False,
                    'error': 'Message not found'
                }

            # Call provider-specific status check
            status = SMSService._check_delivery_status(provider, message_id)

            # Return combined status
            return {
                'found': True,
                'message_id': message_id,
                **status
            }

        except Exception as e:
            logger.error(f"Error checking SMS delivery status: {str(e)}")
            return {
                'found': False,
                'error': f'Status check failed: {str(e)}'
            }

    @staticmethod
    def test_connection(provider: Optional[str] = None) -> Dict[str, Any]:
        """
        Test connection to the SMS provider.

        Args:
            provider: Provider to test (uses default if not specified)

        Returns:
            Dictionary with test results
        """
        # Get provider from config if not specified
        if not provider and has_app_context():
            provider = current_app.config.get('SMS_PROVIDER', SMSProvider.TWILIO)
        elif not provider:
            provider = SMSProvider.TWILIO

        try:
            # Check if SMS is configured
            if not SMSService._is_sms_configured(provider):
                return {
                    'success': False,
                    'error': f'SMS provider {provider} not configured'
                }

            # Call provider-specific test connection function
            if provider == SMSProvider.TWILIO:
                return SMSService._test_twilio_connection()
            elif provider == SMSProvider.AWS_SNS:
                return SMSService._test_aws_connection()
            elif provider == SMSProvider.MESSAGEBIRD:
                return SMSService._test_messagebird_connection()
            elif provider == SMSProvider.VONAGE:
                return SMSService._test_vonage_connection()
            elif provider == SMSProvider.MOCK:
                return {
                    'success': True,
                    'message': 'Mock provider connection successful',
                    'details': {'provider': 'mock'}
                }
            else:
                return {
                    'success': False,
                    'error': f'Unsupported provider: {provider}'
                }

        except Exception as e:
            logger.error(f"Error testing SMS connection to {provider}: {str(e)}")
            return {
                'success': False,
                'error': f'Connection test failed: {str(e)}'
            }

    @staticmethod
    def _check_rate_limit(recipient: str) -> bool:
        """
        Check if SMS sending would exceed rate limits.

        Args:
            recipient: Recipient phone number

        Returns:
            Boolean indicating if sending is allowed
        """
        if not has_app_context() or not hasattr(cache, 'get') or not hasattr(cache, 'set'):
            return True  # If we can't check, assume it's allowed

        # Create a rate limit key for this recipient
        sanitized_recipient = ''.join(c for c in recipient if c.isdigit() or c == '+')
        rate_key = f"sms_ratelimit:{sanitized_recipient}"

        # Get current count and time window
        window = current_app.config.get('SMS_RATE_LIMIT_WINDOW', SMS_RATE_LIMIT_WINDOW)
        max_per_window = current_app.config.get('SMS_RATE_LIMIT_MAX_PER_USER', SMS_RATE_LIMIT_MAX_PER_USER)

        # Get current count
        current_count = cache.get(rate_key) or 0

        # Check if limit exceeded
        if current_count >= max_per_window:
            logger.warning(f"SMS rate limit exceeded: {current_count}/{max_per_window} for {sanitized_recipient}")
            return False

        # Increment count
        cache.set(rate_key, current_count + 1, timeout=window)
        return True

    @staticmethod
    def _is_sms_configured(provider: str) -> bool:
        """
        Check if an SMS provider is properly configured.

        Args:
            provider: Provider name to check

        Returns:
            Boolean indicating if provider is configured
        """
        if not has_app_context():
            # Development/testing fallback
            if provider == SMSProvider.MOCK:
                return True
            return False

        config = current_app.config

        if provider == SMSProvider.TWILIO:
            return (config.get('TWILIO_ACCOUNT_SID') and
                    config.get('TWILIO_AUTH_TOKEN') and
                    config.get('TWILIO_PHONE_NUMBER'))

        elif provider == SMSProvider.AWS_SNS:
            return (config.get('AWS_ACCESS_KEY_ID') and
                    config.get('AWS_SECRET_ACCESS_KEY') and
                    config.get('AWS_REGION'))

        elif provider == SMSProvider.MESSAGEBIRD:
            return config.get('MESSAGEBIRD_API_KEY') is not None

        elif provider == SMSProvider.VONAGE:
            return (config.get('VONAGE_API_KEY') and
                    config.get('VONAGE_API_SECRET'))

        elif provider == SMSProvider.MOCK:
            return True

        return False

    @staticmethod
    def _send_with_provider(
        provider: str,
        to: str,
        message: str,
        sender_id: Optional[str],
        tracking_id: str,
        priority: str,
        retry_count: int,
        category: Optional[str]
    ) -> Dict[str, Any]:
        """
        Send SMS using the specified provider implementation.

        Args:
            provider: SMS provider to use
            to: Recipient phone number
            message: Message content
            sender_id: Sender ID or phone number
            tracking_id: Tracking ID for this message
            priority: Priority level
            retry_count: Number of retry attempts
            category: Notification category

        Returns:
            Dictionary with status and details
        """
        start_time = datetime.now()

        # Normalize phone number
        verification = SMSService.verify_phone_number(to)
        if not verification.get('valid', False):
            return {
                'success': False,
                'error': verification.get('error', 'Invalid phone number'),
                'tracking_id': tracking_id
            }

        # Use verified formatted number
        recipient = verification.get('formatted', to)

        # Check provider and call appropriate function
        try:
            if provider == SMSProvider.TWILIO:
                return SMSService._send_with_twilio(recipient, message, sender_id, tracking_id, priority)

            elif provider == SMSProvider.AWS_SNS:
                return SMSService._send_with_aws_sns(recipient, message, sender_id, tracking_id, priority)

            elif provider == SMSProvider.MESSAGEBIRD:
                return SMSService._send_with_messagebird(recipient, message, sender_id, tracking_id, priority)

            elif provider == SMSProvider.VONAGE:
                return SMSService._send_with_vonage(recipient, message, sender_id, tracking_id, priority)

            elif provider == SMSProvider.MOCK:
                return SMSService._send_with_mock(recipient, message, sender_id, tracking_id, priority)

            else:
                return {
                    'success': False,
                    'error': f'Unsupported provider: {provider}',
                    'tracking_id': tracking_id
                }

        except Exception as e:
            # Log error and duration
            duration_ms = (datetime.now() - start_time).total_seconds() * 1000
            logger.error(f"Error sending SMS via {provider}: {str(e)}")
            metrics.increment('sms.error')
            metrics.timing('sms.duration', duration_ms)

            return {
                'success': False,
                'error': f'Provider error: {str(e)}',
                'tracking_id': tracking_id,
                'duration_ms': duration_ms
            }

    @staticmethod
    def _send_with_twilio(
        to: str,
        message: str,
        sender_id: Optional[str],
        tracking_id: str,
        priority: str
    ) -> Dict[str, Any]:
        """Send SMS using Twilio provider."""
        start_time = datetime.now()

        try:
            from twilio.rest import Client

            if not has_app_context():
                return {
                    'success': False,
                    'error': 'No application context',
                    'tracking_id': tracking_id
                }

            config = current_app.config
            account_sid = config.get('TWILIO_ACCOUNT_SID')
            auth_token = config.get('TWILIO_AUTH_TOKEN')
            from_number = sender_id or config.get('TWILIO_PHONE_NUMBER')

            if not (account_sid and auth_token and from_number):
                return {
                    'success': False,
                    'error': 'Twilio configuration incomplete',
                    'tracking_id': tracking_id
                }

            client = Client(account_sid, auth_token)

            # Add messaging service SID if available for high priority messages
            messaging_service_sid = None
            if priority in (SMS_CRITICAL_PRIORITY, SMS_HIGH_PRIORITY):
                messaging_service_sid = config.get('TWILIO_MESSAGING_SERVICE_SID')

            # Set parameters based on whether we're using a messaging service or direct sender
            if messaging_service_sid:
                message_params = {
                    'messaging_service_sid': messaging_service_sid,
                    'to': to,
                    'body': message
                }
            else:
                message_params = {
                    'from_': from_number,
                    'to': to,
                    'body': message
                }

            # Send the message
            twilio_message = client.messages.create(**message_params)

            # Calculate duration
            duration_ms = (datetime.now() - start_time).total_seconds() * 1000
            metrics.timing('sms.twilio.duration', duration_ms)

            return {
                'success': True,
                'provider_message_id': twilio_message.sid,
                'tracking_id': tracking_id,
                'status': twilio_message.status,
                'duration_ms': duration_ms
            }

        except ImportError:
            return {
                'success': False,
                'error': 'Twilio library not installed',
                'tracking_id': tracking_id
            }
        except Exception as e:
            duration_ms = (datetime.now() - start_time).total_seconds() * 1000
            return {
                'success': False,
                'error': str(e),
                'tracking_id': tracking_id,
                'duration_ms': duration_ms
            }

    @staticmethod
    def _send_with_aws_sns(
        to: str,
        message: str,
        sender_id: Optional[str],
        tracking_id: str,
        priority: str
    ) -> Dict[str, Any]:
        """Send SMS using AWS SNS provider."""
        start_time = datetime.now()

        try:
            import boto3

            if not has_app_context():
                return {
                    'success': False,
                    'error': 'No application context',
                    'tracking_id': tracking_id
                }

            config = current_app.config
            aws_access_key = config.get('AWS_ACCESS_KEY_ID')
            aws_secret_key = config.get('AWS_SECRET_ACCESS_KEY')
            aws_region = config.get('AWS_REGION')

            if not (aws_access_key and aws_secret_key and aws_region):
                return {
                    'success': False,
                    'error': 'AWS configuration incomplete',
                    'tracking_id': tracking_id
                }

            # Initialize SNS client
            session = boto3.Session(
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=aws_region
            )

            sns = session.client('sns')

            # Set message attributes based on priority
            message_attributes = {
                'AWS.SNS.SMS.SenderID': {
                    'DataType': 'String',
                    'StringValue': sender_id or config.get('AWS_SNS_SENDER_ID', 'CloudPlatform')
                }
            }

            # Set delivery preference based on priority
            if priority in (SMS_CRITICAL_PRIORITY, SMS_HIGH_PRIORITY):
                message_attributes['AWS.SNS.SMS.SMSType'] = {
                    'DataType': 'String',
                    'StringValue': 'Transactional'
                }
            else:
                message_attributes['AWS.SNS.SMS.SMSType'] = {
                    'DataType': 'String',
                    'StringValue': 'Promotional'
                }

            # Send the message
            response = sns.publish(
                PhoneNumber=to,
                Message=message,
                MessageAttributes=message_attributes
            )

            duration_ms = (datetime.now() - start_time).total_seconds() * 1000
            metrics.timing('sms.aws_sns.duration', duration_ms)

            return {
                'success': True,
                'provider_message_id': response.get('MessageId'),
                'tracking_id': tracking_id,
                'status': 'sent',  # SNS doesn't provide immediate delivery status
                'duration_ms': duration_ms
            }

        except ImportError:
            return {
                'success': False,
                'error': 'AWS boto3 library not installed',
                'tracking_id': tracking_id
            }
        except Exception as e:
            duration_ms = (datetime.now() - start_time).total_seconds() * 1000
            return {
                'success': False,
                'error': str(e),
                'tracking_id': tracking_id,
                'duration_ms': duration_ms
            }

    @staticmethod
    def _send_with_messagebird(
        to: str,
        message: str,
        sender_id: Optional[str],
        tracking_id: str,
        priority: str
    ) -> Dict[str, Any]:
        """Send SMS using MessageBird provider."""
        start_time = datetime.now()

        try:
            import messagebird

            if not has_app_context():
                return {
                    'success': False,
                    'error': 'No application context',
                    'tracking_id': tracking_id
                }

            config = current_app.config
            api_key = config.get('MESSAGEBIRD_API_KEY')

            if not api_key:
                return {
                    'success': False,
                    'error': 'MessageBird configuration incomplete',
                    'tracking_id': tracking_id
                }

            client = messagebird.Client(api_key)

            # Set originator (sender ID or phone number)
            originator = sender_id or config.get('MESSAGEBIRD_ORIGINATOR', 'CloudPlatform')

            # Determine sending type based on priority
            msg_type = 'flash' if priority == SMS_CRITICAL_PRIORITY else 'sms'

            # Send the message
            mb_message = client.message_create(
                originator=originator,
                recipients=[to],
                body=message,
                type=msg_type
            )

            duration_ms = (datetime.now() - start_time).total_seconds() * 1000
            metrics.timing('sms.messagebird.duration', duration_ms)

            return {
                'success': True,
                'provider_message_id': mb_message.id,
                'tracking_id': tracking_id,
                'status': mb_message.status,
                'duration_ms': duration_ms
            }

        except ImportError:
            return {
                'success': False,
                'error': 'MessageBird library not installed',
                'tracking_id': tracking_id
            }
        except Exception as e:
            duration_ms = (datetime.now() - start_time).total_seconds() * 1000
            return {
                'success': False,
                'error': str(e),
                'tracking_id': tracking_id,
                'duration_ms': duration_ms
            }

    @staticmethod
    def _send_with_vonage(
        to: str,
        message: str,
        sender_id: Optional[str],
        tracking_id: str,
        priority: str
    ) -> Dict[str, Any]:
        """Send SMS using Vonage (formerly Nexmo) provider."""
        start_time = datetime.now()

        try:
            import vonage

            if not has_app_context():
                return {
                    'success': False,
                    'error': 'No application context',
                    'tracking_id': tracking_id
                }

            config = current_app.config
            api_key = config.get('VONAGE_API_KEY')
            api_secret = config.get('VONAGE_API_SECRET')

            if not (api_key and api_secret):
                return {
                    'success': False,
                    'error': 'Vonage configuration incomplete',
                    'tracking_id': tracking_id
                }

            client = vonage.Client(key=api_key, secret=api_secret)
            sms = vonage.Sms(client)

            # Set sender
            from_number = sender_id or config.get('VONAGE_BRAND_NAME', 'CloudPlatform')

            # Send the message with appropriate type
            is_unicode = not all(ord(c) < 128 for c in message)

            response = sms.send_message({
                'from': from_number,
                'to': to,
                'text': message,
                'type': 'unicode' if is_unicode else 'text',
                'client-ref': tracking_id  # For tracking
            })

            duration_ms = (datetime.now() - start_time).total_seconds() * 1000
            metrics.timing('sms.vonage.duration', duration_ms)

            # Check response format
            message_count = len(response["messages"])
            first_message = response["messages"][0]

            if first_message.get("status") == "0":
                return {
                    'success': True,
                    'provider_message_id': first_message.get('message-id'),
                    'tracking_id': tracking_id,
                    'status': 'sent',
                    'message_count': message_count,
                    'duration_ms': duration_ms
                }
            else:
                error = first_message.get('error-text', 'Unknown error')
                return {
                    'success': False,
                    'error': error,
                    'tracking_id': tracking_id,
                    'duration_ms': duration_ms
                }

        except ImportError:
            return {
                'success': False,
                'error': 'Vonage library not installed',
                'tracking_id': tracking_id
            }
        except Exception as e:
            duration_ms = (datetime.now() - start_time).total_seconds() * 1000
            return {
                'success': False,
                'error': str(e),
                'tracking_id': tracking_id,
                'duration_ms': duration_ms
            }

    @staticmethod
    def _send_with_mock(
        to: str,
        message: str,
        sender_id: Optional[str],
        tracking_id: str,
        priority: str
    ) -> Dict[str, Any]:
        """Mock implementation for testing."""
        # Simulate processing time
        import time
        time.sleep(0.1)

        # Log the mock message
        logger.info(f"MOCK SMS to {to}: {message} (priority: {priority}, tracking: {tracking_id})")

        # Simulate a message ID
        mock_message_id = f"mock-{uuid.uuid4().hex[:12]}"

        return {
            'success': True,
            'provider_message_id': mock_message_id,
            'tracking_id': tracking_id,
            'status': 'delivered',  # Always successful in mock mode
            'duration_ms': 100,  # Simulated duration
            'mock': True
        }

    @staticmethod
    def _log_sms_attempt(
        tracking_id: str,
        recipient: str,
        message: str,
        priority: str,
        category: Optional[str]
    ) -> None:
        """
        Log SMS attempt to database for tracking.

        Args:
            tracking_id: Message tracking ID
            recipient: Recipient phone number
            message: Message content (truncated)
            priority: Priority level
            category: Optional category
        """
        try:
            # Create new SMS delivery log
            if hasattr(db, 'session') and hasattr(db.session, 'add'):
                # This assumes you have a model for tracking SMS deliveries
                # If not, this can be simplified to just log the attempt
                try:
                    from models.communication.comm_log import CommunicationLog

                    # Create log entry
                    log_entry = CommunicationLog(
                        channel_type='sms',
                        recipient_address=recipient,
                        message_type=priority,
                        tracking_id=tracking_id,
                        content_snippet=message[:50] + ('...' if len(message) > 50 else ''),
                        category=category,
                        status='queued',
                        created_at=datetime.now(timezone.utc)
                    )

                    db.session.add(log_entry)
                    db.session.commit()
                except ImportError:
                    # If model not available, just log the attempt
                    logger.info(f"SMS queued: {tracking_id} to {recipient} ({priority})")
        except Exception as e:
            # Non-critical error - log but don't block sending
            logger.warning(f"Failed to log SMS attempt: {str(e)}")

    @staticmethod
    def _get_provider_for_message(message_id: str) -> Optional[str]:
        """
        Get the provider used for a specific message.

        Args:
            message_id: Message ID

        Returns:
            String provider name or None if not found
        """
        # First try to determine from the ID format
        if message_id.startswith('SM'):
            return SMSProvider.TWILIO
        elif message_id.startswith('mock-'):
            return SMSProvider.MOCK

        # Check the database
        try:
            from models.communication.comm_log import CommunicationLog

            log_entry = CommunicationLog.query.filter_by(tracking_id=message_id, channel_type='sms').first()
            if log_entry and log_entry.provider:
                return log_entry.provider
        except:
            pass

        # If we can't determine, use the default
        if has_app_context():
            return current_app.config.get('SMS_PROVIDER', SMSProvider.TWILIO)

        return None

    @staticmethod
    def _check_delivery_status(provider: str, message_id: str) -> Dict[str, Any]:
        """
        Check delivery status for a message with the provider.

        Args:
            provider: Provider name
            message_id: Message ID

        Returns:
            Dictionary with status details
        """
        if provider == SMSProvider.TWILIO:
            return SMSService._check_twilio_status(message_id)
        elif provider == SMSProvider.AWS_SNS:
            return {'status': 'unknown', 'detail': 'AWS SNS does not support status checking'}
        elif provider == SMSProvider.MESSAGEBIRD:
            return SMSService._check_messagebird_status(message_id)
        elif provider == SMSProvider.VONAGE:
            return SMSService._check_vonage_status(message_id)
        elif provider == SMSProvider.MOCK:
            return {'status': 'delivered', 'delivery_time': datetime.now(timezone.utc).isoformat()}

        return {'status': 'unknown', 'error': f'Unsupported provider: {provider}'}

    @staticmethod
    def _check_twilio_status(message_id: str) -> Dict[str, Any]:
        """Check SMS status with Twilio."""
        try:
            from twilio.rest import Client

            if not has_app_context():
                return {'status': 'unknown', 'error': 'No application context'}

            config = current_app.config
            account_sid = config.get('TWILIO_ACCOUNT_SID')
            auth_token = config.get('TWILIO_AUTH_TOKEN')

            if not (account_sid and auth_token):
                return {'status': 'unknown', 'error': 'Twilio configuration incomplete'}

            client = Client(account_sid, auth_token)
            message = client.messages(message_id).fetch()

            return {
                'status': message.status,
                'delivery_time': message.date_sent.isoformat() if message.date_sent else None,
                'error_code': message.error_code,
                'error_message': message.error_message
            }
        except ImportError:
            return {'status': 'unknown', 'error': 'Twilio library not installed'}
        except Exception as e:
            return {'status': 'unknown', 'error': str(e)}

    @staticmethod
    def _check_messagebird_status(message_id: str) -> Dict[str, Any]:
        """Check SMS status with MessageBird."""
        try:
            import messagebird

            if not has_app_context():
                return {'status': 'unknown', 'error': 'No application context'}

            config = current_app.config
            api_key = config.get('MESSAGEBIRD_API_KEY')

            if not api_key:
                return {'status': 'unknown', 'error': 'MessageBird configuration incomplete'}

            client = messagebird.Client(api_key)
            message = client.message(message_id)

            return {
                'status': message.status,
                'delivery_time': message.recipients['items'][0]['statusDatetime'] if message.recipients else None,
                'recipient_count': len(message.recipients['items']) if message.recipients else 0
            }
        except ImportError:
            return {'status': 'unknown', 'error': 'MessageBird library not installed'}
        except Exception as e:
            return {'status': 'unknown', 'error': str(e)}

    @staticmethod
    def _check_vonage_status(message_id: str) -> Dict[str, Any]:
        """Check SMS status with Vonage."""
        try:
            import vonage

            if not has_app_context():
                return {'status': 'unknown', 'error': 'No application context'}

            config = current_app.config
            api_key = config.get('VONAGE_API_KEY')
            api_secret = config.get('VONAGE_API_SECRET')

            if not (api_key and api_secret):
                return {'status': 'unknown', 'error': 'Vonage configuration incomplete'}

            client = vonage.Client(key=api_key, secret=api_secret)
            sms = vonage.Sms(client)

            # Try to get delivery receipt
            try:
                response = sms.get_message_status(message_id)
                return {
                    'status': response.get('message-state', 'unknown'),
                    'delivery_time': response.get('message-timestamp'),
                    'network': response.get('network', 'unknown')
                }
            except:
                return {'status': 'unknown', 'detail': 'Receipt not available'}

        except ImportError:
            return {'status': 'unknown', 'error': 'Vonage library not installed'}
        except Exception as e:
            return {'status': 'unknown', 'error': str(e)}

    @staticmethod
    def _test_twilio_connection() -> Dict[str, Any]:
        """Test connection to Twilio."""
        try:
            from twilio.rest import Client

            if not has_app_context():
                return {'success': False, 'error': 'No application context'}

            config = current_app.config
            account_sid = config.get('TWILIO_ACCOUNT_SID')
            auth_token = config.get('TWILIO_AUTH_TOKEN')

            if not (account_sid and auth_token):
                return {'success': False, 'error': 'Twilio configuration incomplete'}

            # Initialize client and make simple API call
            client = Client(account_sid, auth_token)
            account = client.api.accounts(account_sid).fetch()

            return {
                'success': True,
                'message': 'Twilio connection successful',
                'details': {
                    'account_name': account.friendly_name,
                    'account_status': account.status,
                    'account_type': account.type
                }
            }
        except ImportError:
            return {'success': False, 'error': 'Twilio library not installed'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def _test_aws_connection() -> Dict[str, Any]:
        """Test connection to AWS SNS."""
        try:
            import boto3

            if not has_app_context():
                return {'success': False, 'error': 'No application context'}

            config = current_app.config
            aws_access_key = config.get('AWS_ACCESS_KEY_ID')
            aws_secret_key = config.get('AWS_SECRET_ACCESS_KEY')
            aws_region = config.get('AWS_REGION')

            if not (aws_access_key and aws_secret_key and aws_region):
                return {'success': False, 'error': 'AWS configuration incomplete'}

            # Initialize SNS client and verify connectivity
            session = boto3.Session(
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=aws_region
            )

            sns = session.client('sns')

            # Simple API call to check connectivity
            response = sns.get_sms_attributes()

            return {
                'success': True,
                'message': 'AWS SNS connection successful',
                'details': {
                    'sms_attributes': response.get('attributes', {})
                }
            }
        except ImportError:
            return {'success': False, 'error': 'AWS boto3 library not installed'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def _test_messagebird_connection() -> Dict[str, Any]:
        """Test connection to MessageBird."""
        try:
            import messagebird

            if not has_app_context():
                return {'success': False, 'error': 'No application context'}

            config = current_app.config
            api_key = config.get('MESSAGEBIRD_API_KEY')

            if not api_key:
                return {'success': False, 'error': 'MessageBird configuration incomplete'}

            # Initialize client and make simple API call
            client = messagebird.Client(api_key)
            balance = client.balance()

            return {
                'success': True,
                'message': 'MessageBird connection successful',
                'details': {
                    'balance': balance.amount,
                    'currency': balance.type,
                    'payment_method': balance.payment
                }
            }
        except ImportError:
            return {'success': False, 'error': 'MessageBird library not installed'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def _test_vonage_connection() -> Dict[str, Any]:
        """Test connection to Vonage."""
        try:
            import vonage

            if not has_app_context():
                return {'success': False, 'error': 'No application context'}

            config = current_app.config
            api_key = config.get('VONAGE_API_KEY')
            api_secret = config.get('VONAGE_API_SECRET')

            if not (api_key and api_secret):
                return {'success': False, 'error': 'Vonage configuration incomplete'}

            # Initialize client and make simple API call
            client = vonage.Client(key=api_key, secret=api_secret)
            account = client.account.get_balance()

            return {
                'success': True,
                'message': 'Vonage connection successful',
                'details': {
                    'balance': account['value'],
                    'auto_reload': account['auto_reload']
                }
            }
        except ImportError:
            return {'success': False, 'error': 'Vonage library not installed'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def _filter_by_preferences(
        recipients: List[str],
        category: Optional[str],
        priority: str
    ) -> List[str]:
        """
        Filter recipients based on their notification preferences.

        Args:
            recipients: List of recipients to filter
            category: Notification category
            priority: Priority level

        Returns:
            Filtered list of recipients
        """
        if not USER_PREFERENCES_AVAILABLE:
            return recipients

        try:
            from models.communication.user_preference import NotificationPreference
            from models import User

            # Get all users with SMS enabled
            users_with_sms = {}
            for pref in NotificationPreference.query.filter_by(sms_enabled=True).all():
                users_with_sms[pref.user_id] = pref

            if not users_with_sms:
                return []

            # Get all users with phone numbers matching these recipients
            filtered_recipients = []
            sanitized_recipients = [''.join(c for c in num if c.isdigit() or c == '+') for num in recipients]

            for user in User.query.filter(User.phone_number.in_(sanitized_recipients)).all():
                # Check if this user has SMS notifications enabled
                if user.id not in users_with_sms:
                    continue

                pref = users_with_sms[user.id]

                # Check category subscription if specified
                if category and hasattr(pref, 'subscribed_categories'):
                    subscribed = pref.subscribed_categories or []
                    if category not in subscribed:
                        continue

                # Check priority threshold
                if hasattr(pref, 'priority_threshold'):
                    threshold = pref.priority_threshold

                    # Map priorities to levels
                    priority_levels = {
                        SMS_LOW_PRIORITY: 0,
                        SMS_MEDIUM_PRIORITY: 1,
                        SMS_HIGH_PRIORITY: 2,
                        SMS_CRITICAL_PRIORITY: 3
                    }

                    threshold_levels = {
                        NotificationPreference.PRIORITY_THRESHOLD_LOW: 0,
                        NotificationPreference.PRIORITY_THRESHOLD_MEDIUM: 1,
                        NotificationPreference.PRIORITY_THRESHOLD_HIGH: 2,
                        NotificationPreference.PRIORITY_THRESHOLD_CRITICAL: 3
                    }

                    # Skip if priority is below threshold
                    if priority_levels.get(priority, 1) < threshold_levels.get(threshold, 0):
                        continue

                # Check quiet hours
                if hasattr(pref, 'quiet_hours_enabled') and pref.quiet_hours_enabled:
                    # Skip non-critical messages during quiet hours
                    if priority != SMS_CRITICAL_PRIORITY and SMSService._is_quiet_hour(pref):
                        continue

                # If passed all checks, include this recipient
                filtered_recipients.append(user.phone_number)

            return filtered_recipients
        except Exception as e:
            logger.error(f"Error filtering recipients by preference: {str(e)}")
            return recipients

    @staticmethod
    def _is_quiet_hour(pref) -> bool:
        """
        Check if current time is within quiet hours.

        Args:
            pref: User preference object with quiet hours settings

        Returns:
            Boolean indicating if current time is in quiet hours
        """
        try:
            import pytz
            from datetime import datetime, time

            # Get timezone
            tz_name = pref.quiet_hours_timezone or 'UTC'
            tz = pytz.timezone(tz_name)

            # Parse quiet hours
            start_hours, start_mins = map(int, pref.quiet_hours_start.split(':'))
            end_hours, end_mins = map(int, pref.quiet_hours_end.split(':'))

            start_time = time(start_hours, start_mins)
            end_time = time(end_hours, end_mins)

            # Get current time in user's timezone
            current = datetime.now(pytz.utc).astimezone(tz)
            current_time = current.time()

            # Check if current time is in quiet hours
            if start_time <= end_time:
                # Simple case: quiet hours within same day
                return start_time <= current_time <= end_time
            else:
                # Complex case: quiet hours span midnight
                return current_time >= start_time or current_time <= end_time

        except Exception as e:
            logger.warning(f"Error checking quiet hours: {str(e)}")
            return False


# Helper functions for module-level access
def send_sms(to: str, message: str, **kwargs) -> Dict[str, Any]:
    """
    Send an SMS message.

    Args:
        to: Recipient phone number
        message: Message content
        **kwargs: Additional parameters (priority, tracking_id, category, etc.)

    Returns:
        Dictionary with delivery status
    """
    return SMSService.send_sms(to=to, message=message, **kwargs)

def send_bulk_sms(recipients: List[str], message: str, **kwargs) -> Dict[str, Any]:
    """
    Send SMS messages to multiple recipients.

    Args:
        recipients: List of phone numbers
        message: Message content
        **kwargs: Additional parameters

    Returns:
        Dictionary with delivery statistics
    """
    return SMSService.send_bulk_sms(recipients=recipients, message=message, **kwargs)

def verify_phone_number(phone_number: str) -> Dict[str, Any]:
    """
    Verify a phone number's validity and format.

    Args:
        phone_number: Phone number to verify

    Returns:
        Dictionary with verification results
    """
    return SMSService.verify_phone_number(phone_number)

def test_sms_configuration(provider: Optional[str] = None) -> Dict[str, Any]:
    """
    Test SMS provider configuration.

    Args:
        provider: Provider to test (uses default if not specified)

    Returns:
        Dictionary with test results
    """
    return SMSService.test_connection(provider)


# Export symbols that should be available when importing the package
__all__ = [
    # Classes
    'SMSService',
    'SMSProvider',

    # Functions
    'send_sms',
    'send_bulk_sms',
    'verify_phone_number',
    'test_sms_configuration'
]
