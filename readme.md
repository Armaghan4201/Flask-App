# Early Warning Text System

A sophisticated Flask-based emergency notification platform that monitors multiple authoritative data sources for critical events (natural disasters, power outages, space weather, and government disaster declarations) and delivers real-time alerts via SMS and email to subscribers with full TCPA compliance.

## 🚀 Key Features

### **Multi-Source Event Monitoring**
* **GDACS Integration**: Global Disaster Alert and Coordination System monitoring
* **NOAA Space Weather**: Real-time solar flare and space weather tracking
* **EIA Power Grid**: US power outage and grid stability monitoring
* **FEMA Disaster Declarations**: Government emergency declarations
* **PowerOutage.us Email Forwarding**: Automated email alert forwarding system
* **FX Rates Monitoring**: Currency exchange rate notifications

### **Advanced User Management**
* **Secure Authentication**: Flask-Login with password strength validation
* **User Dashboard**: Account management and notification preferences
* **Profile Management**: Update contact information and notification settings
* **TCPA Compliance**: Full SMS consent tracking with digital signatures
* **Legal Compliance**: Age verification, IP tracking, and comprehensive audit trails

### **Dual-Channel Notifications**
* **SMS Alerts**: Twilio integration with international number support
* **Email Notifications**: Gmail API with OAuth2 authentication
* **Smart Delivery**: User preference-based notification routing
* **Compliance Features**: Automatic STOP/HELP command handling

### **Administrative Features**
* **Gmail Email Forwarding**: Monitor and forward PowerOutage.us alerts
* **Event Management**: View and manage recent events
* **User Analytics**: Account statistics and notification metrics
* **System Monitoring**: API status and authentication management

### **Production-Ready Architecture**
* **Background Processing**: APScheduler for automated monitoring
* **Event Deduplication**: Prevent duplicate notifications
* **Error Resilience**: Graceful handling of API failures
* **Data Retention**: Automated 30-day event cleanup
* **Security**: Comprehensive input validation and secure session management

## 📊 Monitored Events & Thresholds

### **Natural Disasters (GDACS)**
| Event Type | Threshold | Source |
|------------|-----------|---------|
| Earthquakes | 8.0+ magnitude | GDACS |
| Tsunamis | All alerts | GDACS |
| Tropical Cyclones | All alerts | GDACS |
| Floods | Orange alert level | GDACS |
| Droughts | Orange alert level | GDACS |
| Forest Fires | Orange alert level | GDACS |
| Volcanic Eruptions | Green alert level | GDACS |

### **Space Weather (NOAA)**
| Event Type | Threshold | Source |
|------------|-----------|---------|
| Solar Flares | X-class | NOAA SWPC |
| Coronal Mass Ejections | Earth-directed | NOAA SWPC |
| Geomagnetic Storms | G3+ level | NOAA SWPC |

### **Infrastructure (EIA)**
| Event Type | Threshold | Source |
|------------|-----------|---------|
| Power Outages | 20%+ of US affected | EIA |
| Grid Instability | Major events | EIA |

### **Government Alerts (FEMA)**
| Event Type | Threshold | Source |
|------------|-----------|---------|
| Major Disaster Declarations | All DR types | FEMA |

## 🛠️ Installation & Setup

### **Prerequisites**
- Python 3.8+
- Twilio Account (for SMS)
- Google Cloud Project with Gmail API enabled
- EIA API Key (free registration)
- FX Rates API Key (optional)

### **1. Clone Repository**
```bash
git clone <repository-url>
cd early-warning-text
```

### **2. Create Virtual Environment**
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

### **3. Install Dependencies**
```bash
pip install -r requirements.txt
```

### **4. Environment Configuration**
Create a `.env` file in the project root:

```env
# Flask Configuration
SECRET_KEY=your-super-secret-key-here
PORT=5000

# Database Configuration
DATABASE_URL=sqlite:///app.db

# Twilio Configuration (SMS)
TWILIO_ACCOUNT_SID=your-twilio-account-sid
TWILIO_AUTH_TOKEN=your-twilio-auth-token
TWILIO_PHONE_NUMBER=+1234567890

# Gmail API Configuration
GMAIL_API_TOKEN=static/token.json
GMAIL_API_CREDENTIALS=static/gmail_api_credentials.json

# API Keys
EIA_API_KEY=your-eia-api-key
FX_API_TOKEN=your-fx-rates-api-token

# Power Outage Email Configuration
POWER_OUTAGE_EMAIL_SENDER=alerts@alerts.poweroutage.us
POWER_OUTAGE_EMAIL_CHECK_HOURS=1
```

### **5. Gmail API Setup**
1. Create a Google Cloud Project
2. Enable Gmail API
3. Create OAuth 2.0 credentials (Desktop Application)
4. Download credentials JSON file to `static/gmail_api_credentials.json`

### **6. Database Initialization**
```bash
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

### **7. Run Application**
```bash
python app.py
```

Access the application at `http://localhost:5000`

### **8. Gmail Authorization (Required)**
Visit `http://localhost:5000/authorize` to complete Gmail OAuth setup.

## 🔧 Configuration

### **Event Thresholds** (`config.py`)
```python
# Earthquake magnitude threshold
EARTHQUAKE_MAGNITUDE_THRESHOLD = 8.0

# GDACS alert levels
DROUGHT_ALERT_LEVEL = "Orange"
FOREST_FIRE_ALERT_LEVEL = "Orange"
FLOOD_ALERT_LEVEL = "Orange"
ERUPTION_ALERT_LEVEL = "Green"

# Space weather
SOLAR_XRAY_THRESHOLD = 'X'

# Power outages
POWER_OUTAGE_THRESHOLD_PERCENT = 20

# API polling interval (minutes)
API_CHECK_INTERVAL = 30
```

### **Monitoring Sources**
| API | Purpose | Authentication |
|-----|---------|----------------|
| GDACS | Natural disasters | None required |
| NOAA SWPC | Space weather | None required |
| EIA | Power grid data | API key required |
| FEMA | Disaster declarations | None required |
| Gmail API | Email forwarding | OAuth 2.0 |
| Twilio | SMS delivery | Account credentials |
| FX Rates | Currency monitoring | API key (optional) |

## 📱 User Features

### **Registration Process**
1. **Account Creation**: Basic information and preferences
2. **SMS Consent** (Optional): TCPA-compliant consent form with:
   - Digital signature verification
   - Age verification (18+)
   - Legal consent tracking
   - IP address and browser logging

### **User Dashboard**
- Account overview and statistics
- Notification preference management
- Recent event history
- Quick action buttons

### **Profile Management**
- Update personal information
- Modify notification preferences
- Change password with strength validation
- Account deletion with safeguards

## 🔒 Legal Compliance & Security

### **TCPA Compliance**
- **Explicit Consent**: Digital signature required for SMS
- **Age Verification**: 18+ requirement with date validation
- **Opt-out Mechanisms**: STOP/HELP command handling
- **Audit Trails**: Complete consent tracking with IP/timestamp
- **Legal Documentation**: Comprehensive consent agreements

### **Security Features**
- **Password Security**: Werkzeug hashing with strength requirements
- **Session Management**: Flask-Login with secure cookies
- **Input Validation**: Multi-layer validation (client/server)
- **OAuth2 Security**: Secure Gmail API integration
- **CSRF Protection**: Form validation and security headers

## 🔧 Administrative Features

### **Power Outage Email Management**
Access via `/admin/power-outage-emails`:
- Monitor Gmail for PowerOutage.us alerts
- Manual email processing triggers
- Event tracking and notifications
- Gmail authentication status

### **System Monitoring**
- API connection status
- Event processing metrics
- User notification statistics
- Error tracking and logging

## 🚀 Production Deployment

### **Environment Setup**
1. **Security**: Update `SECRET_KEY` with secure random value
2. **Database**: Configure production database (PostgreSQL recommended)
3. **Debug Mode**: Set `debug=False` in production
4. **SSL/TLS**: Enable HTTPS for OAuth and security
5. **Environment Variables**: Secure credential management

### **Recommended Stack**
- **WSGI Server**: Gunicorn with multiple workers
- **Reverse Proxy**: Nginx for static files and SSL termination
- **Database**: PostgreSQL for production reliability
- **Monitoring**: APM integration for performance tracking
- **Caching**: Redis for session storage and caching

### **Example Production Command**
```bash
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

## 📊 Architecture Overview

### **Core Components**
- **Flask Application**: Main web framework with blueprint organization
- **Background Scheduler**: APScheduler for automated API monitoring
- **Database Layer**: SQLAlchemy with Flask-Migrate for schema management
- **Authentication**: Flask-Login for secure user sessions
- **Notification System**: Dual-channel delivery (SMS/Email)

### **Data Flow**
1. **Monitoring**: Background jobs check APIs every 18 seconds
2. **Processing**: Events filtered against configured thresholds
3. **Deduplication**: Unique event IDs prevent duplicate notifications
4. **Delivery**: Notifications sent via Twilio (SMS) and Gmail (Email)
5. **Compliance**: SMS consent verified before delivery
6. **Cleanup**: Events automatically removed after 30 days

## 📝 API Documentation

### **Event API**
- `GET /api/events` - Retrieve recent events (JSON)
- Parameters: `days` (filter), `limit` (max 100)

### **User Management**
- `POST /signup` - Create new user account
- `POST /login` - User authentication
- `GET /dashboard` - User dashboard (authenticated)
- `PUT /profile` - Update user preferences (authenticated)

## 🐛 Troubleshooting

### **Common Issues**
1. **Gmail Authentication**: Ensure OAuth credentials are correctly configured
2. **SMS Delivery**: Verify Twilio credentials and phone number format
3. **API Failures**: Check API keys and network connectivity
4. **Database Errors**: Ensure migrations are up to date

### **Debugging**
- Check `app.log` for detailed error information
- Verify environment variables are loaded correctly
- Test API connections individually
- Monitor background scheduler status

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📞 Support

For issues and questions:
- Create an issue on GitHub
- Email: earlywarningtext@gmail.com
- Phone: +18448414316