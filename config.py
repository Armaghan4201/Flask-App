# config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY')
    
    # Database settings
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # API keys and credentials
    TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID')
    TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN')
    TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER')
    
    # Gmail API credentials
    GMAIL_API_TOKEN = os.environ.get('GMAIL_API_TOKEN')
    GMAIL_API_CREDENTIALS = os.environ.get('GMAIL_API_CREDENTIALS')
    GMAIL_API_SCOPES = [
        'https://www.googleapis.com/auth/gmail.send',
        'https://www.googleapis.com/auth/gmail.readonly',
        ]
    
    # Power Outage Email Forwarding Configuration
    POWER_OUTAGE_EMAIL_SENDER = os.environ.get('POWER_OUTAGE_EMAIL_SENDER')
    POWER_OUTAGE_EMAIL_CHECK_HOURS = 1

    # API endpoints and keys
    EIA_API_KEY = os.environ.get('EIA_API_KEY')
    EIA_API_URL = 'https://api.eia.gov/v2/nuclear-outages/us-nuclear-outages/data/?frequency=daily&data[0]=percentOutage&sort[0][column]=period&sort[0][direction]=desc&offset=0&length=5000'
    NOAA_SPACE_WEATHER_API = 'https://services.swpc.noaa.gov/json/goes/primary'
    FEMA_API_URL = 'https://www.fema.gov/api/open/v2/DisasterDeclarationsSummaries'
    FX_API_URL = 'https://api.fxratesapi.com/latest'
    FX_API_TOKEN = os.environ.get('FX_API_TOKEN')
    UPTIMEROBOT_API_KEY = os.environ.get('UPTIMEROBOT_API_KEY')
    
    # API polling interval (in minutes)
    API_CHECK_INTERVAL = 30
    
    ## Event threshold settings
    # GDACS
    EARTHQUAKE_MAGNITUDE_THRESHOLD = 8.0
    DROUGHT_ALERT_LEVEL = "Orange"
    FOREST_FIRE_ALERT_LEVEL = "Orange"
    FLOOD_ALERT_LEVEL = "Orange"
    ERUPTION_ALERT_LEVEL = "Green"
    # NOAA
    SOLAR_XRAY_THRESHOLD = 'X'
    # EIA
    POWER_OUTAGE_THRESHOLD_PERCENT = 20
    # FEMA
    FEMA_HOURS = None
    FEMA_TOP = 3