# app/api_monitor.py
from gdacs.api import GDACSAPIReader
import re
import json 
import requests
from datetime import datetime, timedelta, timezone
from app import db
from app.models import Event, User
from app.notification import send_notifications, send_email, send_sms
from app.email_forwarder import check_power_outage_emails
from app.sms_stop_handler import SMSStopHandler
from app.uptimerobot_checker import check_uptimerobot_monitors
from flask import current_app as app
import logging
from icecream import ic

logger = logging.getLogger(__name__)

# New logger for below-threshold events
below_threshold_logger = logging.getLogger("below_threshold")
below_threshold_logger.setLevel(logging.INFO)

if not below_threshold_logger.handlers:
    file_handler = logging.FileHandler("Below Threshold Events.log")
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    below_threshold_logger.addHandler(file_handler)

def schedule_sms_stop_checks(scheduler, flask_app):
    """Schedule periodic SMS STOP checks"""
    interval = flask_app.config['API_CHECK_INTERVAL']  # e.g., 60 minutes

    def run_with_app_context(func):
        def wrapper():
            with flask_app.app_context():
                func()
        return wrapper
    
    # Schedule the job to run the SMS Stop Processor every interval
    scheduler.add_job(run_with_app_context(run_sms_stop_processor), 
                      'interval', minutes=interval, id='sms_stop_check')

    logger.info(f"Scheduled SMS STOP check every {interval} minutes")

def run_sms_stop_processor():
    """Scheduled task to process SMS STOP messages"""
    with app.app_context():
        try:
            logger.info("Running scheduled SMS STOP processor")
            handler = SMSStopHandler(app)
            results = handler.process_recent_messages(days_back=1, limit=100)  # Check the last 1 day, with a limit of 100 messages

            logger.info(
                f"SMS STOP processing completed: "
                f"{results['total_messages']} messages checked, "
                f"{results['stop_requests']} STOP requests found, "
                f"{results['users_processed']} users processed"
            )
            
            if results['errors']:
                logger.warning(f"Errors encountered: {len(results['errors'])}")
                for error in results['errors'][:5]:  # Log first 5 errors
                    logger.warning(f"Error: {error}")

            return results
        
        except Exception as e:
            logger.error(f"Error in scheduled SMS STOP processor: {str(e)}")
            return None

def schedule_api_checks(scheduler, flask_app):
    """Schedule periodic API checks"""
    interval = flask_app.config['API_CHECK_INTERVAL']
    
    # Create a wrapper function that provides app context
    def run_with_app_context(func):
        def wrapper():
            with flask_app.app_context():  # Use the passed app instance
                func()
        return wrapper
    
    # Schedule all API checks with app context wrappers
    scheduler.add_job(run_with_app_context(check_gdacs_api), 
                     'interval', minutes=interval, id='gdacs_check')
    
    scheduler.add_job(run_with_app_context(check_noaa_space_weather), 
                     'interval', minutes=interval, id='noaa_check')
    
    scheduler.add_job(run_with_app_context(check_eia_api), 
                     'interval', minutes=interval, id='eia_check')
    
    scheduler.add_job(run_with_app_context(check_fema_api), 
                     'interval', minutes=interval, id='fema_check')
    
    scheduler.add_job(run_with_app_context(check_fx_api), 
                     'interval', minutes=interval, id='fx_check')
    
    # Add power outage email checking
    scheduler.add_job(run_with_app_context(check_power_outage_emails), 
                     'interval', minutes=interval, id='power_outage_email_check')
    
    # Add uptimerobot checking
    scheduler.add_job(run_with_app_context(check_uptimerobot_monitors), 
                  'interval', minutes=interval, id='uptimerobot_check')

    # Add a job to clean up old events
    scheduler.add_job(run_with_app_context(Event.cleanup_old_events), 
                     'interval', hours=24, id='cleanup_events')
    
    logger.info(f"Scheduled API checks every {interval} minutes")
    logger.info("Power outage email forwarding scheduled")

def check_gdacs_api():
    """Check GDACS API for disaster alerts"""
    try:
        logger.info("Checking GDACS API")
        
        # Create a new GDACS client
        client = GDACSAPIReader()
        
        # Fetch latest events from GDACS
        response = client.latest_events()
        
        # Process the response using regex to extract features
        response_str = str(response)
        if "features=[" not in response_str:
            logger.error("No features found in GDACS response")
            return
        
        matches = re.search(r"features=\[(.*)\]", response_str, re.DOTALL)
        if not matches:
            logger.error("Could not extract features from GDACS response")
            return
        
        # Reconstruct proper JSON format
        features_text = "[" + matches.group(1) + "]"
        features_text = features_text.replace("'", '"')  # Replace single quotes with double quotes
        
        event_type_mapping = {
            'dr': 'Drought',
            'wf': 'Forest Fire',
            'tc': 'Tropical Cyclone',
            'vo': 'Volcanic Eruption',
            'eq': 'Earthquake',
            'fl': 'Flood',
        }
        try:
            # Parse as JSON
            all_features = json.loads(features_text)
            
            # Process each event
            for feature in all_features:
                properties = feature.get('properties', {})
                
                # Get event details
                event_id = properties.get('eventid')
                alert_level = properties.get('alertlevel')
                event_type = properties.get('eventtype', '').lower()
                episode_alert_level = properties.get("episodealertlevel", "")

                # Get severity from severitydata if available, or directly if not
                severity_data = properties.get('severitydata', {})
                if isinstance(severity_data, dict) and 'severity' in severity_data:
                    severity = severity_data.get('severity')
                else:
                    severity = properties.get('severity')
                
                # Skip if missing critical fields
                if not event_id or not event_type or severity is None:
                    continue
                
                if event_type == 'eq' and float(severity) >= app.config['EARTHQUAKE_MAGNITUDE_THRESHOLD']:
                    reason = f"{event_type_mapping[event_type]} with magnitude {severity} exceeds threshold of {app.config['EARTHQUAKE_MAGNITUDE_THRESHOLD']}"
                else:
                    reason = f"Event Skipped. {event_type_mapping[event_type]} with magnitude {severity} detected below Threshold."
                    below_threshold_logger.info(reason)
                    continue
                
                if event_type == 'dr' and episode_alert_level == app.config['DROUGHT_ALERT_LEVEL']:
                    reason = f"{event_type_mapping[event_type]} with Episode Alert Level {episode_alert_level} exceeds threshold of {app.config['DROUGHT_ALERT_LEVEL']}"
                
                elif event_type == 'wf' and episode_alert_level == app.config['FOREST_FIRE_ALERT_LEVEL']:
                    reason = f"{event_type_mapping[event_type]} with Episode Alert Level {episode_alert_level} exceeds threshold of {app.config['FOREST_FIRE_ALERT_LEVEL']}"
                
                elif event_type == 'fl' and episode_alert_level == app.config['FLOOD_ALERT_LEVEL']:
                    reason = f"{event_type_mapping[event_type]} with Episode Alert Level {episode_alert_level} exceeds threshold of {app.config['FLOOD_ALERT_LEVEL']}"
                
                elif event_type == 'vo' and episode_alert_level == app.config['ERUPTION_ALERT_LEVEL']:
                    reason = f"{event_type_mapping[event_type]} with Episode Alert Level {episode_alert_level} exceeds threshold of {app.config['ERUPTION_ALERT_LEVEL']}"

                else:
                    reason = f"Event Skipped. {event_type_mapping[event_type]} with Episode Alert Level {episode_alert_level} falls below Threshold."
                    below_threshold_logger.info(reason)
                    continue

                # Check if we've already processed this event
                existing_event = Event.query.filter_by(event_id=event_id).first()
                if existing_event:
                    continue
                
                # Create new event
                location = properties.get('country') or properties.get('location')
                description = properties.get('title') or properties.get('name')
                
                new_event = Event(
                    event_id=event_id,
                    source='GDACS',
                    event_type=event_type,
                    episode_alert_level=episode_alert_level,
                    severity=str(severity),
                    location=location,
                    description=description,
                    timestamp=datetime.utcnow(),
                    raw_data=json.dumps(properties)
                )
                
                db.session.add(new_event)
                db.session.commit()
                
                # Send notifications
                send_notifications(new_event, reason)
                
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing GDACS JSON: {str(e)}")
        except Exception as e:
            logger.error(f"Error processing GDACS event: {str(e)}")
            
    except Exception as e:
        logger.error(f"Error checking GDACS API: {str(e)}")

def check_noaa_space_weather():
    """Check NOAA Space Weather API for solar events"""
    try:
        logger.info("Checking NOAA Space Weather API")
        
        # Get X-ray flux data
        xray_url = f"{app.config['NOAA_SPACE_WEATHER_API']}/xrays-3-day.json"
        response = requests.get(xray_url)
        response.raise_for_status()
        data = response.json()
        
        # Process only the most recent data point
        if data and len(data) > 0:
            latest = data[-1]
            
            # Generate a unique ID based on timestamp
            event_time = datetime.fromisoformat(latest.get('time_tag', '').replace('Z', '+00:00'))
            event_id = f"SOLAR_XRAY_{event_time.strftime('%Y%m%d%H%M')}"
            
            # Check if we've seen this event before
            existing_event = Event.query.filter_by(event_id=event_id).first()
            if existing_event:
                return
            
            # Check for X-class flares (classification starts with 'X')
            flux = latest.get('flux')
            if flux is None:
                return
                
            # Convert flux to classification
            classification = classify_xray_flux(flux)
            
            # Only process X-class flares
            if not classification.startswith(app.config['SOLAR_XRAY_THRESHOLD']):
                reason = f"Event Skipped. {classification[0]}-class solar flare detected with classification {classification}"
                below_threshold_logger.info(reason)
                return
                
            # Create new event
            new_event = Event(
                event_id=event_id,
                source='NOAA',
                event_type='solar_flare',
                severity=classification,
                location='Sun',
                description=f"{app.config['SOLAR_XRAY_THRESHOLD']}-class solar flare detected: {classification}",
                timestamp=event_time,
                raw_data=json.dumps(latest)
            )
            
            db.session.add(new_event)
            db.session.commit()
            
            # Send notifications
            reason = f"{app.config['SOLAR_XRAY_THRESHOLD']}-class solar flare detected with classification {classification}"
            send_notifications(new_event, reason)
            
    except Exception as e:
        logger.error(f"Error checking NOAA Space Weather API: {str(e)}")

def classify_xray_flux(flux):
    """Convert X-ray flux to classification (A, B, C, M, X)"""
    if flux < 1e-7:
        return f"A{flux/1e-8:.1f}"
    elif flux < 1e-6:
        return f"B{flux/1e-7:.1f}"
    elif flux < 1e-5:
        return f"C{flux/1e-6:.1f}"
    elif flux < 1e-4:
        return f"M{flux/1e-5:.1f}"
    else:
        return f"X{flux/1e-4:.1f}"

def check_eia_api():
    """Check EIA API for power statistics"""
    try:
        logger.info("Checking EIA API")
        
        # For this example, we'll check electricity outage data
        # In a real implementation, you would need to determine the appropriate endpoint
        # and process the response to identify outages.
        api_key = app.config['EIA_API_KEY']
        if not api_key:
            logger.error("EIA API key not configured")
            return
        
        today = datetime.today().date()
        yesterday = today - timedelta(days=1)

        response = requests.get(
            url=app.config['EIA_API_URL'], 
            params={
                'api_key': api_key,
                'start': yesterday,
                'end': today,
                }
            )
        
        response.raise_for_status()
        data = response.json()
        
        # Process data to identify outages
        # This is simplified and would need to be adapted to the actual data structure
        # and methodology for identifying outages
        
        # Example logic (would need to be updated for actual API response):
        total_outage_percent = calculate_outage_percentage(data)

        if total_outage_percent >= app.config['POWER_OUTAGE_THRESHOLD_PERCENT']:
            # Generate event ID based on date
            event_id = f"POWER_OUTAGE_{datetime.utcnow().strftime('%Y%m%d')}"
            
            # Check if we've already reported this outage today
            existing_event = Event.query.filter_by(event_id=event_id).first()
            if existing_event:
                return
                
            # Create new event
            new_event = Event(
                event_id=event_id,
                source='EIA',
                event_type='power_outage',
                severity=f"{total_outage_percent:.1f}%",
                location='United States',
                description=f"Major power outage affecting approximately {total_outage_percent:.1f}% of the US",
                timestamp=datetime.utcnow(),
                raw_data=json.dumps({"outage_percent": total_outage_percent})
            )
            
            db.session.add(new_event)
            db.session.commit()
            
            # Send notifications
            send_notifications(new_event, reason="Power Outage Crossed Threshold")
        else:
            reason = f"Event Skipped. {total_outage_percent:.1f}% Power Outage detected. Below Threshold"
            below_threshold_logger.info(reason)
            return
            
    except Exception as e:
        logger.error(f"Error checking EIA API: {str(e)}")

def calculate_outage_percentage(data):
    """
    Calculate the percentage of US affected by power outages.
    
    Args:
        data (dict): The API response data from EIA
        
    Returns:
        float: The calculated outage percentage
    """
    try:
        # Check if the response has the expected structure
        if 'response' in data and 'data' in data['response']:            
            return float(data['response']['data'][0]['percentOutage'])
        else:
            logger.error("Either 'response' not in json data or 'data' not in 'response'")
    except Exception as e:
        logger.warning(f"Error calculating outage percentage: {e}")
    
    return 0

def check_fema_api():
    """Check FEMA API for disaster declarations."""
    try:
        logger.info("Checking FEMA API")

        # Load parameters from config
        hours = app.config['FEMA_HOURS']
        top    = app.config['FEMA_TOP']

        # Build query parameters
        params = {
            '$orderby': 'declarationDate desc',
            '$top':     top
        }

        # If hours is set, add a date filter
        if hours is not None:
            now_utc    = datetime.now(timezone.utc)
            cutoff     = now_utc - timedelta(hours=hours)
            cutoff_str = cutoff.isoformat(timespec='seconds')
            params['$filter'] = f"declarationDate ge '{cutoff_str}'"
            logger.info(f"Fetching disasters declared since {cutoff_str} UTC …")
        else:
            logger.info(f"No FEMA_HOURS set; fetching top {top} records without date filter")

        # Debug: show full URL
        request_url = requests.Request(
            'GET',
            app.config['FEMA_API_URL'],
            params=params
        ).prepare().url
        logger.debug(f"Request URL: {request_url}")

        # Execute request
        resp = requests.get(app.config['FEMA_API_URL'], params=params)
        resp.raise_for_status()
        data = resp.json()

        # Support both v2 key and OData 'value'
        records = data.get('DisasterDeclarationsSummaries') or data.get('value', [])
        if not records:
            logger.warning(f"No disaster records returned from FEMA API")

        # Process each record
        for disaster in records:
            # Unique event ID
            disaster_id = disaster.get('disasterNumber')
            event_id    = f"FEMA_{disaster_id}"

            # Skip if already seen
            if Event.query.filter_by(event_id=event_id).first():
                continue

            # Only "Major Disaster"
            if disaster.get('declarationType') != 'DR': # DR = Major Disaster
                reason = f"Event Skipped. {disaster.get('declarationType')} Disaster Type Detected. Not a Major Disaster."
                below_threshold_logger.info(reason)
                continue

            # Extract fields
            incident_type    = disaster.get('incidentType')
            state            = disaster.get('state')
            declaration_date = disaster.get('declarationDate')

            # Create and persist new Event
            new_event = Event(
                event_id=   event_id,
                source=     'FEMA',
                event_type= (incident_type or 'disaster').lower(),
                severity=   'Major',
                location=   state,
                description=f"FEMA Major Disaster Declaration: {incident_type} in {state}",
                timestamp=  datetime.fromisoformat(declaration_date) if declaration_date else datetime.utcnow(),
                raw_data=   json.dumps(disaster)
            )
            db.session.add(new_event)
            db.session.commit()

            # Notify subscribers
            send_notifications(new_event)

    except Exception as e:
        logger.error(f"Error checking FEMA API: {e}")

def check_fx_api():
    """Fetch FxRatesAPI latest exchange rates and notify users via email and SMS without storing events."""
    logger.info("Checking FxRatesAPI latest exchange rates")
    try:
        response = requests.get(
            app.config['FX_API_URL'],
            params={'api_key': app.config['FX_API_TOKEN']}
        )
        response.raise_for_status()
        data = response.json()

        # Validate response structure
        if not isinstance(data, dict) or 'rates' not in data:
            logger.error("Unexpected FxRatesAPI response structure")
            return False

        rates = data['rates']

        # Prepare notification content
        subject = "FxRatesAPI: Latest Exchange Rates"
        body_lines = [f"{currency}: {rate}" for currency, rate in rates.items()]
        body = "Latest exchange rates:\n" + "\n".join(body_lines)

        # pkr_rate = data["rates"]["PKR"]
        # body = f"PKR Exchange Rate: {pkr_rate}"

        # Send notifications to all users (email & SMS)
        users = User.query.all()
        for user in users:
            # if user.notify_sms and user.phone_number:
            #     send_sms(user.phone_number, body)
            if user.notify_email and user.email:
                send_email(user.email, subject, body)

        return True

    except requests.exceptions.RequestException as e:
        logger.error(f"Request error while fetching FxRatesAPI: {e}")
        return False
    except ValueError as e:
        logger.error(f"JSON decode error for FxRatesAPI: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error in check_fx_api: {e}")
        return False