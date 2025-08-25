# app/email_forwarder.py
import os
import base64
import json
import logging
from datetime import datetime, timedelta

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from flask import current_app as app

from app import db
from app.models import User, Event
from app.notification import send_email, send_sms
from app.utils.token_utils import load_and_refresh_token
from icecream import ic

logger = logging.getLogger(__name__)

class GmailForwarder:
    """Gmail forwarding service integrated with Flask app"""
    
    def __init__(self):
        self.service = None
        self.authenticate()
    
    def authenticate(self):
        """Authenticate and create Gmail service object using app config"""
        try:
            token_file = app.config.get('GMAIL_API_TOKEN')
            scopes = app.config['GMAIL_API_SCOPES']
            creds = load_and_refresh_token(scopes, token_file)

            self.service = build('gmail', 'v1', credentials=creds)
            logger.info("Gmail service authenticated successfully")
            
        except Exception as e:
            logger.error(f"Error authenticating Gmail service: {e}")
            self.service = None
    
    def get_recent_emails_from_sender(self):
        """Get emails from specific sender within the last N hours"""
        if not self.service:
            logger.error("Gmail service not authenticated")
            return []
            
        try:
            # Calculate time threshold
            time_threshold = datetime.now() - timedelta(hours=self.hours_back)
            
            # Convert to Gmail query format (epoch time)
            after_timestamp = int(time_threshold.timestamp())
            
            # Build search query
            query = f'from:{self.sender_email} after:{after_timestamp}'
            
            logger.info(f"Searching for emails with query: {query}")
            
            # Search for messages
            results = self.service.users().messages().list(
                userId='me', q=query).execute()
            
            messages = results.get('messages', [])
            
            email_details = []
            for message in messages:
                msg = self.service.users().messages().get(
                    userId='me', id=message['id']).execute()
                email_details.append(msg)
            
            return email_details
            
        except HttpError as error:
            logger.error(f'An error occurred while fetching emails: {error}')
            return []
    
    def extract_email_content(self, message):
        """Extract email content and metadata"""
        payload = message['payload']
        headers = payload.get('headers', [])
        
        # Extract headers
        subject = ''
        sender = ''
        date = ''
        
        for header in headers:
            if header['name'] == 'Subject':
                subject = header['value']
            elif header['name'] == 'From':
                sender = header['value']
            elif header['name'] == 'Date':
                date = header['value']
        
        # Extract body
        body = ''
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body']['data']
                    body = base64.urlsafe_b64decode(data).decode('utf-8')
                    break
                elif part['mimeType'] == 'text/html' and not body:
                    # Fallback to HTML if no plain text
                    data = part['body']['data']
                    body = base64.urlsafe_b64decode(data).decode('utf-8')
        else:
            if payload['mimeType'] == 'text/plain':
                data = payload['body']['data']
                body = base64.urlsafe_b64decode(data).decode('utf-8')
            elif payload['mimeType'] == 'text/html':
                data = payload['body']['data']
                body = base64.urlsafe_b64decode(data).decode('utf-8')
        
        return {
            'subject': subject,
            'sender': sender,
            'date': date,
            'body': body,
            'message_id': message['id']
        }
    
    @staticmethod
    def extract_location(email_body):
        lines = email_body.splitlines()
        for line in lines:
            line = line.strip()
            if line.startswith("* "):  # look for lines like "* Georgia [...]"
                state = line[2:].split(" [")[0]  # remove "* " and split before link
                return state
        return None  # if no state found

    def extract_power_outage_info(self, body):
        """Extract only the crucial power outage information between STATES and Update Alert Preferences"""
        try:
            # Find the start and end markers
            start_marker = "STATES"
            end_marker = "Update Alert Preferences"
            
            start_idx = body.find(start_marker)
            end_idx = body.find(end_marker)
            
            if start_idx == -1 or end_idx == -1:
                # Fallback: return first 200 chars if markers not found
                return body[:200].strip()
            
            # Extract the content between markers
            crucial_info = body[start_idx + len(start_marker):end_idx].strip()
            
            # Clean up the extracted text
            # Remove extra whitespace and line breaks
            lines = [line.strip() for line in crucial_info.split('\n') if line.strip()]
            
            # Filter out empty lines and URLs
            filtered_lines = []
            for line in lines:
                # Skip lines that are just URLs or contain only brackets
                if line.startswith('http') or line.startswith('[http') or line == '' or line in ['*', '-']:
                    continue
                # Clean up bullet points and formatting
                line = line.replace('\r', '').replace('* ', '• ')
                if line:
                    filtered_lines.append(line)
            
            return '\n'.join(filtered_lines)
            
        except Exception as e:
            logger.error(f"Error extracting power outage info: {e}")
            # Fallback to first 200 characters
            return body[:200].strip()
    
    def format_sms_message(self, email_content):
        """Format email content for SMS with only crucial information"""
        subject = email_content['subject']
        body = email_content['body']
        
        # Extract only the crucial power outage information
        crucial_info = self.extract_power_outage_info(body)
        
        # Create clean SMS message
        sms_text = f"⚡ {subject}\n\n"
        sms_text += crucial_info
        sms_text += f"\n\n— PowerOutage.us"
        
        # Ensure message fits in SMS limits (1600 chars)
        if len(sms_text) > 1500:
            # Truncate the crucial info if needed
            max_info_length = 1400 - len(f"⚡ {subject}\n\n\n— PowerOutage.us")
            crucial_info = crucial_info[:max_info_length] + "..."
            sms_text = f"⚡ {subject}\n\n{crucial_info}\n\n— PowerOutage.us"
        
        return sms_text
    
    def process_power_outage_email(self, email_content):
        """Process power outage email and send notifications to users"""
        try:
            # Extract key information from the email
            subject = email_content['subject']
            body = email_content['body']
            body_trimmed = '\n'.join(body.splitlines()[2:])
            
            # Create notification content for users
            notification_subject = f"Power Outage Alert: {subject}"
            notification_body = f"""
POWER OUTAGE ALERT

{body_trimmed}

---
This alert was forwarded from poweroutage.us
Visit earlywarningtext.com to manage your notifications
            """
            
            # Get all active users with notifications enabled
            email_users = User.query.filter(
                User.is_active == True,
                User.notify_email == True,
                User.email.isnot(None)
            ).all()
            
            sms_users = User.query.filter(
                User.is_active == True,
                User.notify_sms == True,
                User.phone_number.isnot(None),
                User.sms_consent_given == True,
                User.sms_opted_out == False
            ).all()
            
            # Send email notifications
            email_sent_count = 0
            for user in email_users:
                try:
                    result = send_email(user.email, notification_subject, notification_body)
                    if result:
                        email_sent_count += 1
                        logger.info(f"Sent power outage email to {user.email}")
                    else:
                        raise Exception
                except Exception as e:
                    logger.error(f"Failed to send email to {user.email}: {e}")
            
            # Send SMS notifications using the improved formatting
            sms_body = self.format_sms_message(email_content)
            
            sms_sent_count = 0
            for user in sms_users:
                try:
                    result = send_sms(user.phone_number, sms_body)
                    if result:
                        sms_sent_count += 1
                        logger.info(f"Sent power outage SMS to {user.phone_number}")
                    else:
                        raise Exception
                except Exception as e:
                    logger.error(f"Failed to send SMS to {user.phone_number}: {e}")
            
            logger.info(f"Power outage alert sent to {email_sent_count} email(s) and {sms_sent_count} SMS(s)")
            return email_sent_count + sms_sent_count
            
        except Exception as e:
            logger.error(f"Error processing power outage email: {e}")
            return 0
    
    def check_and_forward_power_outage_alerts(self):
        """Main function to check for power outage alerts and forward them"""
        if not self.service:
            logger.error("Gmail service not authenticated - cannot check for alerts")
            return False
        
        # Power outage email sender
        self.sender_email = app.config.get('POWER_OUTAGE_EMAIL_SENDER')
        self.hours_back = app.config.get('POWER_OUTAGE_EMAIL_CHECK_HOURS')
        
        logger.info(f"Checking for power outage emails from {self.sender_email} in the last {self.hours_back} hour(s)...")
        
        # Get recent emails
        recent_emails = self.get_recent_emails_from_sender()
        
        if not recent_emails:
            logger.info("No new power outage emails found.")
            return True
        
        logger.info(f"Found {len(recent_emails)} power outage email(s) to process.")
        
        # Process each email
        processed_count = 0
        for email_msg in recent_emails:
            email_content = self.extract_email_content(email_msg)
            location = self.extract_location(email_content['body'])
            
            # Create event record for tracking
            event_id = f"POWER_OUTAGE_EMAIL_{email_content['message_id']}"
            
            # Check if we've already processed this email
            existing_event = Event.query.filter_by(event_id=event_id).first()
            if existing_event:
                logger.info(f"Power outage email '{email_content['subject']}' already processed, skipping")
                continue
            
            # Process and send notifications
            notification_count = self.process_power_outage_email(email_content)
            
            if notification_count > 0:
                # Create event record
                new_event = Event(
                    event_id=event_id,
                    source='poweroutage.us',
                    event_type='Power Outage Alert',
                    severity='ALERT',
                    location=location,
                    description=f"Power Outage Alert: {email_content['subject']}",
                    timestamp=datetime.utcnow(),
                    raw_data=json.dumps(email_content),
                    notification_sent=True
                )
                
                db.session.add(new_event)
                db.session.commit()
                processed_count += 1
                
                logger.info(f"Successfully processed power outage email: {email_content['subject']}")
            
        logger.info(f"Successfully processed {processed_count} power outage emails")
        return True

# Scheduler function for integration with existing API monitoring
def check_power_outage_emails():
    """Scheduled function to check for power outage emails"""
    try:
        logger.info("Starting scheduled power outage email check")
        
        # Initialize forwarder
        forwarder = GmailForwarder()
        
        # Check if authentication was successful
        if forwarder.service is None:
            logger.error("Gmail authentication failed. Cannot check for power outage emails.")
            return False
        
        # Check and forward alerts
        success = forwarder.check_and_forward_power_outage_alerts()
        
        if success:
            logger.info("Power outage email check completed successfully")
        else:
            logger.error("Power outage email check failed")
            
        return success
        
    except Exception as e:
        logger.error(f"Error in check_power_outage_emails: {e}")
        return False
