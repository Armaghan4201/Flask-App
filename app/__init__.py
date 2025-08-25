# app/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from apscheduler.schedulers.background import BackgroundScheduler
from config import Config
import os

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
scheduler = BackgroundScheduler()

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

def create_app(config_class=Config):
    app = Flask(
        __name__,
        static_folder = os.path.join(PROJECT_ROOT, 'static'),
        static_url_path = '/static',
        template_folder = os.path.join(PROJECT_ROOT, 'app', 'templates')
    )
    app.config.from_object(config_class)
    
    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    
    # Initialize Flask-Login
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return User.query.get(int(user_id))
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    # Register blueprints
    from app.routes import main
    app.register_blueprint(main)
    
    # Start the scheduler
    if not scheduler.running:
        scheduler.start()
        
    # Import and register jobs here to avoid circular imports
    from app.api_monitor import schedule_api_checks, schedule_sms_stop_checks
    with app.app_context():
        schedule_api_checks(scheduler, app)
        schedule_sms_stop_checks(scheduler, app)
    
    return app