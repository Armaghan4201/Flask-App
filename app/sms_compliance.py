# app/sms_compliance.py
"""
SMS Compliance utilities for TCPA compliance
"""

from app import db
from app.models import User
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class SMSComplianceError(Exception):
    """Exception raised for SMS compliance violations"""
    pass

def can_send_sms_to_user(user_id):
    """
    Check if we can legally send SMS to a user
    Returns (can_send: bool, reason: str)
    """
    user = User.query.get(user_id)
    if not user:
        return False, "User not found"
    
    if not user.is_active:
        return False, "User account is inactive"
    
    if not user.phone_number:
        return False, "No phone number provided"
    
    if not user.sms_consent_given:
        return False, "SMS consent not given"
    
    if user.sms_opted_out:
        return False, "User has opted out of SMS"
    
    if not user.notify_sms:
        return False, "SMS notifications disabled in preferences"
    
    return True, "OK"

def get_sms_eligible_users():
    """
    Get all users who can legally receive SMS messages
    """
    return User.query.filter(
        User.is_active == True,
        User.phone_number.isnot(None),
        User.sms_consent_given == True,
        User.sms_opted_out == False,
        User.notify_sms == True
    ).all()

def handle_sms_stop_request(phone_number):
    """
    Handle STOP request from Twilio webhook
    """
    user = User.query.filter_by(phone_number=phone_number).first()
    if user:
        user.revoke_sms_consent()
        db.session.commit()
        logger.info(f"SMS STOP processed for user {user.id} ({user.email})")
        return True
    return False

def handle_sms_help_request(phone_number):
    """
    Handle HELP request from Twilio webhook
    Returns help message
    """
    return ("EarlyWarningText SMS Help: Text STOP to opt out. "
            "For support: info@earlywarningtext.com or (555) 123-4567. "
            "Standard rates may apply.")

def log_sms_attempt(user_id, phone_number, message, success, error_reason=None):
    """
    Log SMS sending attempts for compliance audit trail
    """
    logger.info(f"SMS attempt: user_id={user_id}, phone={phone_number}, "
                f"success={success}, error={error_reason}")

def validate_sms_content(message):
    """
    Validate SMS message content for compliance
    """
    if len(message) > 1600:  # Twilio limit
        raise SMSComplianceError("Message too long")
    
    return True

def send_compliant_sms(user_id, message):
    """
    Send SMS with full compliance checking
    """
    # Check if we can send
    can_send, reason = can_send_sms_to_user(user_id)
    if not can_send:
        raise SMSComplianceError(f"Cannot send SMS: {reason}")
    
    user = User.query.get(user_id)
    
    # Validate content
    validate_sms_content(message)
    
    # Add compliance footer if not already present
    footer = "\n\nReply STOP to opt out, HELP for help."
    if footer not in message:
        message += footer
    
    try:
        # Import your existing SMS sending logic here
        # from app.notification import send_sms
        # success = send_sms(user.phone_number, message)
        
        # For now, just log
        logger.info(f"Would send SMS to {user.phone_number}: {message}")
        success = True  # Placeholder
        
        log_sms_attempt(user_id, user.phone_number, message, success)
        return success
        
    except Exception as e:
        log_sms_attempt(user_id, user.phone_number, message, False, str(e))
        raise SMSComplianceError(f"Failed to send SMS: {str(e)}")

def generate_consent_report():
    """
    Generate compliance report for auditing
    """
    total_users = User.query.count()
    sms_consent_users = User.query.filter_by(sms_consent_given=True).count()
    sms_opted_out = User.query.filter_by(sms_opted_out=True).count()
    sms_eligible = len(get_sms_eligible_users())
    
    report = {
        'total_users': total_users,
        'sms_consent_given': sms_consent_users,
        'sms_opted_out': sms_opted_out,
        'sms_eligible': sms_eligible,
        'compliance_rate': f"{(sms_consent_users/total_users)*100:.1f}%" if total_users > 0 else "0%",
        'generated_at': datetime.utcnow().isoformat()
    }
    
    return report