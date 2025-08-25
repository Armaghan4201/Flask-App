#!/usr/bin/env python3
"""
SMS Stop Handler for Flask App
Processes STOP replies from Twilio SMS and updates user notification preferences
"""

from twilio.rest import Client
from datetime import datetime, timedelta
import logging
import re
from app import create_app, db
from app.models import User

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SMSStopHandler:
    def __init__(self, app_context=None):
        """Initialize the SMS Stop Handler"""
        if app_context:
            self.app = app_context
        else:
            self.app = create_app()
        
        with self.app.app_context():
            # Get Twilio credentials from Flask config
            self.account_sid = self.app.config.get('TWILIO_ACCOUNT_SID')
            self.auth_token = self.app.config.get('TWILIO_AUTH_TOKEN')
            self.twilio_phone_number = self.app.config.get('TWILIO_PHONE_NUMBER')
            
            if not all([self.account_sid, self.auth_token, self.twilio_phone_number]):
                raise ValueError("Twilio credentials not properly configured in Flask app")
                
            # Initialize Twilio client
            self.client = Client(self.account_sid, self.auth_token)
    
    def get_received_messages(self, limit=50, days_back=7):
        """
        Retrieve only RECEIVED messages (messages sent TO your Twilio number)
        This matches the approach in reading_twilio_sms.py
        
        Args:
            limit (int): Maximum number of messages to retrieve
            days_back (int): How many days back to search for messages
        
        Returns:
            list: List of received message objects only
        """
        try:
            # Calculate date filter
            date_filter = datetime.now() - timedelta(days=days_back)
            
            logger.info(f"Fetching RECEIVED messages for {self.twilio_phone_number}...")
            logger.info(f"Looking back {days_back} days, limit: {limit} messages")
            
            # Fetch only messages sent TO your number (received messages)
            received_messages = self.client.messages.list(
                to=self.twilio_phone_number,
                limit=limit,
                date_sent_after=date_filter
            )
            
            logger.info(f"Found {len(received_messages)} received messages")
            return received_messages
            
        except Exception as e:
            logger.error(f"Error fetching received messages: {str(e)}")
            return []
    
    def is_stop_message(self, message_body):
        """
        Check if a message is a STOP request
        
        Args:
            message_body (str): The message content
            
        Returns:
            bool: True if it's a stop message
        """
        if not message_body:
            return False
            
        # Clean up the message body
        cleaned_message = message_body.strip().upper()
        
        # Check for common stop keywords
        stop_keywords = [
            'STOP', 'UNSUBSCRIBE', 'QUIT', 'CANCEL', 'END', 'REMOVE',
            'OPTOUT', 'OPT-OUT', 'OPT OUT'
        ]
        
        return cleaned_message in stop_keywords
    
    def normalize_phone_number(self, phone_number):
        """
        Normalize phone number format for database lookup
        
        Args:
            phone_number (str): Phone number to normalize
            
        Returns:
            str: Normalized phone number
        """
        if not phone_number:
            return None
            
        # Remove all non-digit characters except plus
        cleaned = re.sub(r'[^\d+]', '', phone_number)
        
        # Ensure it starts with +
        if not cleaned.startswith('+'):
            # If it's a US number starting with 1, add +
            if cleaned.startswith('1') and len(cleaned) == 11:
                cleaned = '+' + cleaned
            # If it's a 10-digit US number, add +1
            elif len(cleaned) == 10:
                cleaned = '+1' + cleaned
            else:
                cleaned = '+' + cleaned
        
        return cleaned
    
    def find_user_by_phone(self, phone_number):
        """
        Find user by phone number in database
        
        Args:
            phone_number (str): Phone number to search for
            
        Returns:
            User: User object if found, None otherwise
        """
        normalized_phone = self.normalize_phone_number(phone_number)
        if not normalized_phone:
            return None
            
        with self.app.app_context():
            # Try exact match first
            user = User.query.filter_by(phone_number=normalized_phone).first()
            
            if not user:
                # Try without country code for US numbers
                if normalized_phone.startswith('+1'):
                    alt_phone = normalized_phone[2:]  # Remove +1
                    user = User.query.filter_by(phone_number=alt_phone).first()
                
                # Try with +1 for numbers without it
                elif not normalized_phone.startswith('+1') and len(normalized_phone.replace('+', '')) == 10:
                    alt_phone = '+1' + normalized_phone.replace('+', '')
                    user = User.query.filter_by(phone_number=alt_phone).first()
            
            return user
    
    def process_stop_request(self, user, message):
        """
        Process a STOP request for a user
        
        Args:
            user (User): User object
            message: Twilio message object
        """
        with self.app.app_context():
            try:
                # Revoke SMS consent and disable SMS notifications
                user.revoke_sms_consent()
                
                db.session.add(user)
                db.session.commit()
                
                logger.info(f"Processed STOP request for user {user.email} (phone: {user.phone_number})")
                
                # Send confirmation SMS
                self.send_stop_confirmation(user.phone_number)
                
                return True
                
            except Exception as e:
                logger.error(f"Error processing STOP request for user {user.email}: {str(e)}")
                db.session.rollback()
                return False
    
    def send_stop_confirmation(self, phone_number):
        """
        Send confirmation SMS for STOP request
        
        Args:
            phone_number (str): Phone number to send confirmation to
        """
        try:
            confirmation_message = (
                "You have been unsubscribed from SMS notifications. "
                "You can re-enable them by logging into your account at earlywarningtext.com. "
                "Reply HELP for assistance."
            )
            
            message = self.client.messages.create(
                body=confirmation_message,
                from_=self.twilio_phone_number,
                to=phone_number
            )
            
            logger.info(f"Stop confirmation sent to {phone_number}, SID: {message.sid}")
            
        except Exception as e:
            logger.error(f"Error sending stop confirmation to {phone_number}: {str(e)}")
    
    def process_recent_messages(self, days_back=1, limit=100):
        """
        Process recent messages for STOP requests
        
        Args:
            days_back (int): How many days back to check
            limit (int): Maximum messages to process
            
        Returns:
            dict: Summary of processing results
        """
        results = {
            'total_messages': 0,
            'stop_requests': 0,
            'users_found': 0,
            'users_processed': 0,
            'errors': []
        }
        
        logger.info(f"Processing recent messages for STOP requests (last {days_back} days)")
        
        # Get received messages
        messages = self.get_received_messages(limit=limit, days_back=days_back)
        results['total_messages'] = len(messages)
        
        for message in messages:
            try:
                # Check if it's a STOP message
                if self.is_stop_message(message.body):
                    results['stop_requests'] += 1
                    logger.info(f"Found STOP message from {message.from_}: '{message.body}'")
                    
                    # Find user by phone number
                    user = self.find_user_by_phone(message.from_)
                    
                    if user:
                        results['users_found'] += 1
                        logger.info(f"Found user: {user.email} for phone {message.from_}")
                        
                        # Check if user already opted out
                        if user.sms_opted_out:
                            logger.info(f"User {user.email} already opted out, skipping")
                            continue
                        
                        # Process the STOP request
                        if self.process_stop_request(user, message):
                            results['users_processed'] += 1
                        else:
                            results['errors'].append(f"Failed to process STOP for user {user.email}")
                    else:
                        error_msg = f"No user found for phone number {message.from_}"
                        logger.warning(error_msg)
                        results['errors'].append(error_msg)
                        
            except Exception as e:
                error_msg = f"Error processing message {message.sid}: {str(e)}"
                logger.error(error_msg)
                results['errors'].append(error_msg)
        
        # Log summary
        logger.info(
            f"Processing complete: {results['total_messages']} messages, "
            f"{results['stop_requests']} STOP requests, "
            f"{results['users_processed']} users processed"
        )
        
        return results

def main():
    """
    Main function for command-line usage
    """
    print("SMS STOP Handler")
    print("=" * 50)
    
    try:
        # Initialize handler
        handler = SMSStopHandler()
        
        # Process recent messages
        results = handler.process_recent_messages(days_back=1, limit=50)
        
        # Display results
        print(f"\nProcessing Results:")
        print(f"- Total messages checked: {results['total_messages']}")
        print(f"- STOP requests found: {results['stop_requests']}")
        print(f"- Users found: {results['users_found']}")
        print(f"- Users processed: {results['users_processed']}")
        
        if results['errors']:
            print(f"\nErrors encountered:")
            for error in results['errors']:
                print(f"- {error}")
        
        print("\nDone!")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())