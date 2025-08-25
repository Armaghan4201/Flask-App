# run.py
from app import create_app, db
import logging
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)

# Suppress Twilio logs
logging.getLogger("twilio.http_client").setLevel(logging.WARNING)

app = create_app()
application = app

if __name__ == '__main__':
    with app.app_context():
        # Create database tables if they don't exist
        db.create_all()
    
    # Run the app
    port = int(os.environ.get('PORT', 5000))
    app.run(
        host='0.0.0.0', 
        port=port, 
        debug=True,
        # ssl_context="adhoc",  # For https
        )
