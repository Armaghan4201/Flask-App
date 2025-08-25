# 1. Updated notification.py - Add STOP checking before sending SMS
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow, InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import base64
from email.mime.text import MIMEText
import os
import pickle
import logging
import requests
from requests.auth import HTTPBasicAuth
from flask import current_app as app
from app.models import User, Event
from app import db
from app.utils.token_utils import load_and_refresh_token
from icecream import ic

logger = logging.getLogger(__name__)

def send_notifications(event, reason=None):
    """Send notifications for a given event
    
    Args:
        event: Event object containing alert details
        reason: String explaining why the notification is being sent
    """
    # Log the notification reason
    if reason:
        logger.info(f"\nSending notification for {event.event_type} - Reason: {reason}\n")
    else:
        logger.info(f"\nSending notification for {event.event_type}\n")
    
    # Mark the event as having notifications sent
    event.notification_sent = True
    db.session.add(event)
    db.session.commit()
    
    # Get all active users
    users = User.query.filter_by(is_active=True).all()
    
    # Prepare notification content
    subject = f"Alert: {event.event_type.title()} - {event.episode_alert_level} | {event.severity}"
    body = generate_notification_body(event)
    
    # Send SMS and Email notifications to all users
    sms_sent = 0
    email_sent = 0
    sms_skipped = 0
    
    for user in users:
        # Send SMS if user can receive SMS notifications
        if user.notify_sms and user.phone_number:
            if user.can_send_sms():  # This checks consent and opt-out status
                if send_sms(user.phone_number, body):
                    sms_sent += 1
                else:
                    logger.warning(f"Failed to send SMS to {user.phone_number}")
            else:
                sms_skipped += 1
                logger.info(f"Skipping SMS for user {user.email} - no consent or opted out")
        
        # Send Email if user wants email notifications
        if user.notify_email and user.email:
            try:
                if send_email(user.email, subject, body):
                    email_sent += 1
            except Exception as e:
                logger.warning(f"Could not send email to: {user.email} - {str(e)}")
    
    logger.info(f"Notification summary: {sms_sent} SMS sent, {sms_skipped} SMS skipped, {email_sent} emails sent")

def generate_notification_body(event):
    """Generate notification body based on event type"""
    # Basic template
    message = f"ALERT: {event.event_type.title()} detected\n"
    message += f"Severity: {event.severity}\n"
    
    if event.location:
        message += f"Location: {event.location}\n"
    
    message += f"Time: {event.timestamp.strftime('%Y-%m-%d %H:%M UTC')}\n"
    
    if event.description:
        message += f"Details: {event.description}\n"
    
    message += "\nReply STOP to unsubscribe. This is an automated alert from EarlyWarningText.com"
    
    return message

def send_sms(phone_number, message):
    """Send an SMS via Twilio using requests"""
    try:
        # Get Twilio credentials from config
        account_sid = app.config['TWILIO_ACCOUNT_SID']
        auth_token = app.config['TWILIO_AUTH_TOKEN']
        twilio_number = app.config['TWILIO_PHONE_NUMBER']
        
        if not account_sid or not auth_token or not twilio_number:
            logger.error("Twilio credentials not configured")
            return False
        
        # Construct Twilio API URL
        twilio_url = f'https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json'
        
        # Ensure the phone number is a string and includes the country code
        phone_number = str(phone_number).strip()
        if not phone_number.startswith('+'):
            phone_number = '+' + phone_number
        
        # Prepare payload
        payload = {
            'To': phone_number,
            'From': twilio_number,
            'Body': message
        }
        
        # Send request to Twilio API
        response = requests.post(
            twilio_url,
            data=payload,
            auth=HTTPBasicAuth(account_sid, auth_token)
        )
        
        # Check if request was successful
        if response.status_code >= 200 and response.status_code < 300:
            response_data = response.json()
            logger.info(f"SMS sent to {phone_number}, SID: {response_data.get('sid')}")
            return True
        else:
            logger.error(f"Error sending SMS to {phone_number}: {response.text}")
            return False
        
    except Exception as e:
        logger.error(f"Error sending SMS to {phone_number}: {str(e)}")
        return False

def send_email(email, subject, message):
    """Send an email via Gmail API"""
    try:
        # Check for token
        token = get_gmail_token()
        if not token:
            logger.error("Gmail API token not available")
            return False
        
        # Build Gmail API service
        service = build('gmail', 'v1', credentials=token)
        
        message_obj = create_message('me', email, subject, message)
        
        # Send message
        send_message(service, 'me', message_obj)
        
        logger.info(f"Email sent to {email}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending email to {email}: {str(e)}")
        return False

def get_gmail_token_desktop_app():
    """Get or refresh Gmail API credentials for a desktop app."""
    creds = None
    token_path = app.config.get('GMAIL_API_TOKEN')
    creds_file = app.config.get('GMAIL_API_CREDENTIALS')
    scopes = app.config['GMAIL_API_SCOPES']

    # Load token if it exists
    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, scopes)

    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            with open(token_path, 'w') as token:
                token.write(creds.to_json())
            return creds  # ✅ All good — exit now
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            return None

    # If creds doesn't exist or can't be refreshed, start OAuth flow
    if not os.path.exists(creds_file):
        logger.error("Gmail API credentials file not found")
        return None

    flow = InstalledAppFlow.from_client_secrets_file(
        creds_file,
        scopes=scopes
    )
    creds = flow.run_local_server(port=8080)

    # Save to token.json
    with open(token_path, 'w') as token:
        token.write(creds.to_json())

    return creds

def get_gmail_token():
    """Load Gmail API token and refresh it if expired."""
    token_path = app.config['GMAIL_API_TOKEN']
    scopes = app.config['GMAIL_API_SCOPES']

    if not os.path.exists(token_path):
        raise RuntimeError("No Gmail token found. Please authorize at http://127.0.0.1:5000/authorize first.")

    try:
        creds = load_and_refresh_token(scopes, token_path)
        return creds
    except Exception as e:
        app.logger.error(f"Token load/refresh failed: {e}")
        raise

def create_message(sender, to, subject, message_text):
    """Create a message for Gmail API"""
    message = MIMEText(message_text)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    
    # Encode the message
    raw = base64.urlsafe_b64encode(message.as_bytes())
    raw = raw.decode()
    
    return {'raw': raw}

def send_message(service, user_id, message):
    """Send an email message via Gmail API"""
    try:
        message = service.users().messages().send(userId=user_id, body=message).execute()
        return message
    except Exception as e:
        logger.error(f"Error sending message: {str(e)}")
        raise

def create_welcome_email(username=None):
    """Create a welcome email for new subscribers"""
    subject = "Welcome to Our Service!"
    greeting = f"Hi {username}," if username else "Hi there,"
    
    message = f"""{greeting}

Thank you for subscribing to earlywarningtext.com. We only send messages when catastrophic events occur, so please make us a contact and take steps to make sure of your preparedness at the sending of subsequent messages. Please reply STOP to unsubscribe from further messages.

Best regards,
The EarlyWarningText Team"""
    
    return subject, message

def create_farewell_email(username=None):
    """Create a farewell email for subscribers who are leaving"""
    subject = "We're Sorry to See You Go"
    greeting = f"Hi {username}," if username else "Hi there,"
    
    message = f"""{greeting}

We're sorry to see you go. Thank you for the time you've spent with our service.

Here's what you should know:
- Your account will be deactivated within the next 48 hours
- You can download your data for the next 30 days
- You're welcome back anytime should you decide to return

If you have any feedback about your experience or reasons for leaving, we'd appreciate hearing from you.

Best regards,
The Team"""
    
    return subject, message

def create_welcome_sms(username=None):
    """Create a welcome SMS for new subscribers"""
    greeting = f"Hi {username}!" if username else "Hi there!"
    
    message = f"""{greeting}

Thank you for subscribing to earlywarningtext.com. We only send messages when catastrophic events occur, so please make us a contact and take steps to make sure of your preparedness at the sending of subsequent messages. Please reply STOP to unsubscribe from further messages.

Best regards,
The EarlyWarningText Team"""
    
    return message

def create_farewell_sms(username=None):
    """Create a farewell SMS for subscribers who are leaving"""
    greeting = f"Hi {username}!" if username else "Hi there!"
    message = f"{greeting} Sorry to see you go! Your account will be deactivated in 48hrs. You can return anytime. Thanks for being with us!"
    
    return message