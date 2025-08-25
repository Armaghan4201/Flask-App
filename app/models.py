# app/models.py
from app import db
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    phone_number = db.Column(db.String(20), index=True, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Define notification preferences
    notify_email = db.Column(db.Boolean, default=True)
    notify_sms = db.Column(db.Boolean, default=False)  # Default to False until consent given
    
    # Account verification and status
    is_verified = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    
    # SMS Consent tracking (TCPA Compliance)
    sms_consent_given = db.Column(db.Boolean, default=False)
    sms_consent_date = db.Column(db.DateTime)
    sms_consent_ip = db.Column(db.String(45))  # IPv4/IPv6 address
    sms_consent_user_agent = db.Column(db.String(255))  # Browser info for audit
    date_of_birth = db.Column(db.Date)
    digital_signature = db.Column(db.String(100))  # User's typed name as signature
    
    # Opt-out tracking
    sms_opted_out = db.Column(db.Boolean, default=False)
    sms_optout_date = db.Column(db.DateTime)

    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def give_sms_consent(self, ip_address, user_agent, signature, date_of_birth):
        """Record SMS consent for TCPA compliance"""
        self.sms_consent_given = True
        self.sms_consent_date = datetime.utcnow()
        self.sms_consent_ip = ip_address
        self.sms_consent_user_agent = user_agent
        self.digital_signature = signature
        self.date_of_birth = date_of_birth
        self.notify_sms = True
        self.sms_opted_out = False
    
    def revoke_sms_consent(self):
        """Revoke SMS consent and disable SMS notifications"""
        self.sms_consent_given = False
        self.notify_sms = False
        self.sms_opted_out = True
        self.sms_optout_date = datetime.utcnow()
    
    def can_send_sms(self):
        """Check if user can receive SMS (has consent and not opted out)"""
        return (self.sms_consent_given and 
                not self.sms_opted_out and 
                self.notify_sms and 
                self.phone_number and 
                self.is_active)
    
    def can_receive_sms_notifications(self):
        """Enhanced method to check if user can receive SMS"""
        return self.can_send_sms()
    
    def opt_out_from_sms(self, reason="user_request"):
        """Opt user out from SMS notifications"""
        self.sms_opted_out = True
        self.sms_optout_date = datetime.utcnow()
        self.notify_sms = False
    
    def opt_in_to_sms(self):
        """Opt user back in to SMS notifications"""
        if self.sms_consent_given and self.phone_number:
            self.sms_opted_out = False
            self.notify_sms = True
            self.sms_optout_date = None
            return True
        return False
    
    def __repr__(self):
        return f'<User {self.email}>'

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(100), index=True, unique=True)
    source = db.Column(db.String(50), index=True)  # GDACS, NOAA, EIA, FEMA
    event_type = db.Column(db.String(50), index=True)  # earthquake, solar_flare, power_outage, etc.
    episode_alert_level = db.Column(db.String(50), index=True)  # Green, Orange, etc.
    severity = db.Column(db.String(20))  # Magnitude, class, etc.
    location = db.Column(db.String(100))
    description = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    raw_data = db.Column(db.Text)  # Store original JSON for reference
    
    # Flag if notification was sent
    notification_sent = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<Event {self.event_type} - {self.severity}>'

    @staticmethod
    def cleanup_old_events():
        """Delete events older than one month"""
        one_month_ago = datetime.utcnow() - timedelta(days=30)
        Event.query.filter(Event.timestamp < one_month_ago).delete()
        db.session.commit()