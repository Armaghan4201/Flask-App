# Step-by-step guide to monitor UptimeRobot status and notify users on Email and SMS

import requests
from datetime import datetime
from app.models import Event, User
from app import db
from app.notification import send_email, send_sms
from flask import current_app as app
import logging
from icecream import ic

logger = logging.getLogger(__name__)

# Function to get UptimeRobot monitor statuses
def check_uptimerobot_monitors():
    api_key = app.config['UPTIMEROBOT_API_KEY']
    url = 'https://api.uptimerobot.com/v2/getMonitors'

    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    payload = {
        'api_key': api_key,
        'format': 'json',
        'logs': '1'  # Include logs for better context
    }

    try:
        response = requests.post(url, headers=headers, data=payload)
        response.raise_for_status()
        data = response.json()

        if data.get('stat') != 'ok':
            logger.error(f"Error from UptimeRobot API: {data}")
            return

        monitors = data.get('monitors', [])
        for monitor in monitors:
            monitor_id = monitor['id']
            friendly_name = monitor['friendly_name']
            status = monitor['status']  # 2 = UP, 9 = DOWN, 1 = PAUSED

            if status == 9:
                # Down event
                event_id = f"UPTIMEROBOT_DOWN_{monitor_id}"
                if Event.query.filter_by(event_id=event_id).first():
                    continue  # Skip already processed events

                # Create and log event
                new_event = Event(
                    event_id=event_id,
                    source='UptimeRobot',
                    event_type='website_down',
                    severity='High',
                    location=friendly_name,
                    description=f"{friendly_name} is DOWN as of {datetime.utcnow().isoformat()}.",
                    timestamp=datetime.utcnow(),
                    raw_data=response.text
                )
                db.session.add(new_event)
                db.session.commit()

                notify_users(new_event)

    except Exception as e:
        logger.error(f"Exception while checking UptimeRobot monitors: {str(e)}")

# Notify users by SMS and Email
def notify_users(event):
    users = User.query.filter_by(is_active=True).all()
    subject = f"ALERT: {event.location} is DOWN"
    body = f"Website Monitor Alert\n\nStatus: DOWN\nLocation: {event.location}\nTime: {event.timestamp}\nDetails: {event.description}\n\nReply STOP to unsubscribe."

    for user in users:
        if user.notify_sms and user.phone_number and user.can_send_sms():
            send_sms(user.phone_number, body)
        if user.notify_email and user.email:
            send_email(user.email, subject, body)
