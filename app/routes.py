# app/routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app, session, send_from_directory
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, Event
import logging
import re
from datetime import datetime, date
from google_auth_oauthlib.flow import Flow
from icecream import ic
import os
from .notification import create_welcome_email, create_welcome_sms, create_farewell_email, create_farewell_sms, send_email, send_sms

# FIXME: Remove it when hosting
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Create blueprint
main = Blueprint('main', __name__)
logger = logging.getLogger(__name__)

@main.route('/')
def index():
    """Render the home page"""
    # Get recent events for display
    recent_events = Event.query.order_by(Event.timestamp.desc()).limit(5).all()
    return render_template('index.html', events=recent_events)

@main.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handle user signup"""
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        notify_email = request.form.get('notify_email') == 'on'
        notify_sms = request.form.get('notify_sms') == 'on'
        terms = request.form.get('terms') == 'on'
        
        # Basic validation
        errors = []
        
        # Required field validation
        if not name or not name.strip():
            errors.append('Please provide your name')
        
        if not email:
            errors.append('Email address is required')
        elif not is_valid_email(email):
            errors.append('Please enter a valid email address')
        
        if not password:
            errors.append('Password is required')
        elif not is_valid_password(password):
            errors.append('Password must be at least 8 characters with uppercase, lowercase, and number')
        
        if password != confirm_password:
            errors.append('Passwords do not match')
        
        if phone_number and not is_valid_phone(phone_number):
            errors.append('Please enter a valid phone number')
        
        if not notify_email and not notify_sms:
            errors.append('Please select at least one notification method')
        
        if notify_sms and not phone_number:
            errors.append('Phone number is required for SMS notifications')
        
        if not terms:
            errors.append('You must agree to the terms and conditions')
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('signup.html')
        
        try:
            # Check if user already exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('An account with this email already exists. Please sign in instead.', 'warning')
                return redirect(url_for('main.login'))
            
            # Check phone number if provided
            if phone_number:
                existing_phone = User.query.filter_by(phone_number=phone_number).first()
                if existing_phone:
                    flash('An account with this phone number already exists.', 'warning')
                    return render_template('signup.html')
            
            # If SMS notifications requested, redirect to SMS consent form
            if notify_sms and phone_number:
                # Store signup data in session temporarily
                session['signup_data'] = {
                    'name': name,
                    'email': email,
                    'phone_number': phone_number,
                    'password': password,
                    'notify_email': notify_email,
                    'notify_sms': notify_sms
                }
                return redirect(url_for('main.sms_consent'))
            
            # Create new user without SMS (email only)
            new_user = User(
                name=name,
                email=email,
                phone_number=phone_number,
                notify_email=notify_email,
                notify_sms=False  # Will be enabled after SMS consent if requested
            )
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.commit()
            
            # Log the user in
            login_user(new_user)
            
            flash('Account created successfully! Welcome to Early Warning Text.', 'success')

            # Create and send welcome email
            try:
                subject, email_message = create_welcome_email(name)
                send_email(email, subject, email_message)
            except Exception as e:
                logger.error(f"Error sending welcome email: {str(e)}")
                # Don't fail signup if email fails
            
            return redirect(url_for('main.dashboard'))
            
        except Exception as e:
            logger.error(f"Error in signup: {str(e)}")
            flash('An error occurred while creating your account. Please try again.', 'danger')
            return render_template('signup.html')
            
    # GET request
    return render_template('signup.html')

@main.route('/sms-consent', methods=['GET', 'POST'])
def sms_consent():
    """Handle SMS consent form"""
    if request.method == 'POST':
        # Get stored signup data
        signup_data = session.get('signup_data')
        if not signup_data:
            flash('Session expired. Please start the signup process again.', 'warning')
            return redirect(url_for('main.signup'))
        
        # Get consent form data
        consent_decision = request.form.get('consent_decision')
        digital_signature = request.form.get('digital_signature')
        date_of_birth = request.form.get('date_of_birth')
        age_verification = request.form.get('age_verification') == 'on'
        terms_agreement = request.form.get('terms_agreement') == 'on'
        cell_phone = request.form.get('cell_phone')  # Get phone from form (user can edit it)
        
        # Validation
        errors = []
        
        if not consent_decision:
            errors.append('Please select your consent decision')
        
        if not digital_signature:
            errors.append('Please provide your digital signature')
        elif digital_signature.strip().lower() != signup_data['name'].strip().lower():
            errors.append('Digital signature must match your name exactly')
        
        if not date_of_birth:
            errors.append('Please provide your date of birth')
        else:
            # Validate age (18+)
            try:
                birth_date = datetime.strptime(date_of_birth, '%Y-%m-%d').date()
                today = date.today()
                age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
                if age < 18:
                    errors.append('You must be 18 or older to provide SMS consent')
            except ValueError:
                errors.append('Invalid date of birth format')
        
        if not age_verification:
            errors.append('You must verify that you are 18 or older')
        
        if not terms_agreement:
            errors.append('You must agree to the SMS consent terms')
        
        if not cell_phone:
            errors.append('Please provide your cell phone number')
        elif not is_valid_phone(cell_phone):
            errors.append('Please provide a valid cell phone number')
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('sms_consent.html', 
                                   signup_data=signup_data,
                                   user_name=signup_data['name'],
                                   phone_number=signup_data['phone_number'],
                                   current_date=datetime.now().strftime('%B %d, %Y'),
                                   current_time=datetime.now().strftime('%I:%M %p UTC'),
                                   user_ip=request.remote_addr)
        
        try:
            # Create user account
            new_user = User(
                name=signup_data['name'],
                email=signup_data['email'],
                phone_number=cell_phone,  # Use phone from consent form (in case user edited it)
                notify_email=signup_data['notify_email'],
                notify_sms=False  # Will be set by consent decision
            )
            new_user.set_password(signup_data['password'])
            
            # Set date of birth
            if date_of_birth:
                new_user.date_of_birth = datetime.strptime(date_of_birth, '%Y-%m-%d').date()
            
            # Handle SMS consent
            if consent_decision == 'yes':
                new_user.give_sms_consent(
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', '')[:255],
                    signature=digital_signature,
                    date_of_birth=datetime.strptime(date_of_birth, '%Y-%m-%d').date()
                )
                flash('Account created successfully with SMS notifications enabled!', 'success')
            else:
                # User declined SMS consent
                flash('Account created successfully. SMS notifications are disabled (you can enable them later if you change your mind).', 'info')
            
            db.session.add(new_user)
            db.session.commit()
            
            # Clear session data
            session.pop('signup_data', None)
            
            # Log the user in
            login_user(new_user)
            
            # Create and send welcome email
            try:
                subject, message = create_welcome_email(signup_data['name'])
                send_email(signup_data['email'], subject, message)
                
                sms_message = create_welcome_sms(signup_data['name'])
                send_sms(cell_phone, sms_message)
            except Exception as e:
                logger.error(f"Error sending welcome email: {str(e)}")
                # Don't fail signup if email fails
            
            return redirect(url_for('main.dashboard'))
            
        except Exception as e:
            logger.error(f"Error in SMS consent: {str(e)}")
            flash('An error occurred while processing your consent. Please try again.', 'danger')
            return render_template('sms_consent.html', 
                                   signup_data=signup_data,
                                   user_name=signup_data['name'],
                                   phone_number=signup_data['phone_number'],
                                   current_date=datetime.now().strftime('%B %d, %Y'),
                                   current_time=datetime.now().strftime('%I:%M %p UTC'),
                                   user_ip=request.remote_addr)
    
    # GET request
    signup_data = session.get('signup_data')
    if not signup_data:
        flash('Please complete the signup form first.', 'warning')
        return redirect(url_for('main.signup'))
    
    return render_template('sms_consent.html',
                           signup_data=signup_data,
                           user_name=signup_data['name'],
                           phone_number=signup_data['phone_number'],
                           current_date=datetime.now().strftime('%B %d, %Y'),
                           current_time=datetime.now().strftime('%I:%M %p UTC'),
                           user_ip=request.remote_addr)

@main.route('/admin/sms-stop-handler', methods=['GET', 'POST'])
@login_required
def sms_stop_handler_admin():
    """Admin interface for SMS STOP handling"""
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'process_stop_messages':
            days_back = int(request.form.get('days_back', 1))
            limit = int(request.form.get('limit', 50))
            
            try:
                from app.sms_stop_handler import SMSStopHandler
                
                handler = SMSStopHandler(current_app)
                results = handler.process_recent_messages(
                    days_back=days_back,
                    limit=limit
                )
                
                flash(
                    f'STOP message processing completed! '
                    f'Checked {results["total_messages"]} messages, '
                    f'found {results["stop_requests"]} STOP requests, '
                    f'processed {results["users_processed"]} users.',
                    'success'
                )
                
                if results['errors']:
                    for error in results['errors'][:5]:  # Show first 5 errors
                        flash(f'Error: {error}', 'warning')
                    
                    if len(results['errors']) > 5:
                        flash(f'...and {len(results["errors"]) - 5} more errors', 'warning')
                        
            except Exception as e:
                logger.error(f"Error in SMS STOP handler: {e}")
                flash(f'Error occurred: {str(e)}', 'danger')
        
        return redirect(url_for('main.sms_stop_handler_admin'))
    
    # GET request - show admin page
    # Get recent SMS opt-out events
    recent_optouts = User.query.filter_by(sms_opted_out=True).order_by(User.sms_optout_date.desc()).limit(20).all()
    
    return render_template('admin/sms_stop_handler.html', recent_optouts=recent_optouts)

@main.route('/api/check-sms-stops')
@login_required
def api_check_sms_stops():
    """API endpoint to check and process SMS STOP messages"""
    try:
        from app.sms_stop_handler import SMSStopHandler
        
        # Get parameters
        days_back = request.args.get('days_back', 1, type=int)
        limit = request.args.get('limit', 50, type=int)
        
        # Cap limits for safety
        days_back = min(days_back, 30)
        limit = min(limit, 200)
        
        handler = SMSStopHandler(current_app)
        results = handler.process_recent_messages(
            days_back=days_back,
            limit=limit
        )
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error in API SMS STOP check: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@main.route('/twilio/sms', methods=['POST'])
def twilio_sms_webhook():
    """Handle incoming SMS messages from Twilio webhook"""
    from_number = request.form.get('From')
    message_body = request.form.get('Body', '').strip()
    
    if is_stop_message(message_body):
        # Process the STOP request
        user = find_user_by_phone(from_number)
        
        if user:
            user.revoke_sms_consent()
            db.session.add(user)
            db.session.commit()
            
            send_stop_confirmation_sms(from_number)
        
    return '<?xml version="1.0" encoding="UTF-8"?><Response></Response>', 200, {'Content-Type': 'text/xml'}

def is_stop_message(message_body):
    """Check if a message is a STOP request"""
    if not message_body:
        return False
    
    cleaned_message = message_body.strip().upper()
    stop_keywords = ['STOP', 'UNSUBSCRIBE', 'QUIT', 'CANCEL', 'END', 'REMOVE', 'OPTOUT', 'OPT-OUT', 'OPT OUT']
    
    return cleaned_message in stop_keywords

def find_user_by_phone(phone_number):
    """Find user by phone number in database"""
    if not phone_number:
        return None
    
    # Normalize phone number
    import re
    cleaned = re.sub(r'[^\d+]', '', phone_number)
    
    if not cleaned.startswith('+'):
        if cleaned.startswith('1') and len(cleaned) == 11:
            cleaned = '+' + cleaned
        elif len(cleaned) == 10:
            cleaned = '+1' + cleaned
        else:
            cleaned = '+' + cleaned
    
    # Try exact match first
    user = User.query.filter_by(phone_number=cleaned).first()
    
    if not user:
        # Try alternative formats
        if cleaned.startswith('+1'):
            alt_phone = cleaned[2:]  # Remove +1
            user = User.query.filter_by(phone_number=alt_phone).first()
        elif not cleaned.startswith('+1') and len(cleaned.replace('+', '')) == 10:
            alt_phone = '+1' + cleaned.replace('+', '')
            user = User.query.filter_by(phone_number=alt_phone).first()
    
    return user

def send_stop_confirmation_sms(phone_number):
    """Send confirmation SMS for STOP request"""
    try:
        confirmation_message = (
            "You have been unsubscribed from SMS notifications. "
            "You can re-enable them by logging into your account at earlywarningtext.com. "
            "Reply HELP for assistance."
        )
        
        # Use the existing send_sms function
        send_sms(phone_number, confirmation_message)
        
    except Exception as e:
        logger.error(f"Error sending stop confirmation to {phone_number}: {str(e)}")

@main.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember_me = request.form.get('remember_me') == 'on'
        
        if not email or not password:
            flash('Please provide both email and password.', 'danger')
            return render_template('login.html')
        
        try:
            user = User.query.filter_by(email=email).first()
            
            if user and user.check_password(password):
                if not user.is_active:
                    flash('Your account has been deactivated. Please contact support.', 'warning')
                    return render_template('login.html')
                
                login_user(user, remember=remember_me)
                flash(f'Welcome back, {user.name}!', 'success')
                
                # Redirect to next page or dashboard
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
            else:
                flash('Invalid email or password.', 'danger')
                
        except Exception as e:
            logger.error(f"Error in login: {str(e)}")
            flash('An error occurred during login. Please try again.', 'danger')
    
    return render_template('login.html')

@main.route('/logout')
@login_required
def logout():
    """Handle user logout"""
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('main.index'))

@main.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    # Get recent events for the user
    recent_events = Event.query.order_by(Event.timestamp.desc()).limit(10).all()
    return render_template('dashboard.html', user=current_user, events=recent_events)

@main.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile management"""
    if request.method == 'POST':
        name = request.form.get('name')
        phone_number = request.form.get('phone_number')
        notify_email = request.form.get('notify_email') == 'on'
        
        # Validation
        errors = []
        
        if not name or not name.strip():
            errors.append('Please provide your name')
        
        if phone_number and not is_valid_phone(phone_number):
            errors.append('Please enter a valid phone number')
        
        if not notify_email and not current_user.notify_sms:
            errors.append('You must have at least one notification method enabled')
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('profile.html', user=current_user)
        
        try:
            # Check if phone number already exists for another user
            if phone_number:
                existing_phone = User.query.filter(
                    User.phone_number == phone_number,
                    User.id != current_user.id
                ).first()
                if existing_phone:
                    flash('This phone number is already associated with another account.', 'warning')
                    return render_template('profile.html', user=current_user)
            
            # If phone number is being removed and user has SMS consent, revoke it
            if not phone_number and current_user.phone_number and current_user.sms_consent_given:
                current_user.revoke_sms_consent()
                flash('Phone number removed. SMS notifications have been disabled and consent revoked.', 'warning')
            
            # Update user
            current_user.name = name
            current_user.phone_number = phone_number
            current_user.notify_email = notify_email
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            
        except Exception as e:
            logger.error(f"Error updating profile: {str(e)}")
            flash('An error occurred while updating your profile. Please try again.', 'danger')
    
    return render_template('profile.html', user=current_user)

@main.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change user password"""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not current_password or not new_password or not confirm_password:
            flash('All password fields are required.', 'danger')
            return render_template('change_password.html')
        
        if not current_user.check_password(current_password):
            flash('Current password is incorrect.', 'danger')
            return render_template('change_password.html')
        
        if not is_valid_password(new_password):
            flash('New password must be at least 8 characters with uppercase, lowercase, and number.', 'danger')
            return render_template('change_password.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return render_template('change_password.html')
        
        try:
            current_user.set_password(new_password)
            db.session.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('main.profile'))
            
        except Exception as e:
            logger.error(f"Error changing password: {str(e)}")
            flash('An error occurred while changing your password. Please try again.', 'danger')
    
    return render_template('change_password.html')

@main.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Handle forgot password"""
    if request.method == 'POST':
        email = request.form.get('email')
        
        if not email or not is_valid_email(email):
            flash('Please enter a valid email address.', 'danger')
            return render_template('forgot_password.html')
        
        user = User.query.filter_by(email=email).first()
        if user:
            # In a real application, you would generate a reset token and send an email
            # For this example, we'll just show a success message
            flash('If an account with this email exists, password reset instructions have been sent.', 'info')
        else:
            # Don't reveal if email exists or not for security
            flash('If an account with this email exists, password reset instructions have been sent.', 'info')
        
        return redirect(url_for('main.login'))
    
    return render_template('forgot_password.html')

# Legacy subscribe route for backwards compatibility
@main.route('/subscribe', methods=['GET', 'POST'])
def subscribe():
    """Redirect to signup"""
    return redirect(url_for('main.signup'))

@main.route('/unsubscribe', methods=['GET', 'POST'])
def unsubscribe():
    """Handle user unsubscription - now requires login"""
    if current_user.is_authenticated:
        # User is logged in, they can delete their account
        if request.method == 'POST':
            confirm = request.form.get('confirm_delete')
            if confirm == 'DELETE':
                try:
                    user_email = current_user.email
                    user_name = current_user.name
                    user_number = current_user.phone_number
                    user_notify_sms = current_user.notify_sms
                    
                    db.session.delete(current_user)
                    db.session.commit()
                    
                    logout_user()
                    
                    # Send farewell email
                    try:
                        subject, message = create_farewell_email(user_name)
                        send_email(user_email, subject, message)

                    except Exception as e:
                        logger.error(f"Error sending farewell email: {str(e)}")
                    
                    if user_notify_sms:
                        try:
                            sms_message = create_welcome_sms(user_name)
                            send_sms(user_number, sms_message)
                        except Exception as e:
                            logger.error(f"Error sending farewell sms: {str(e)}")
                    
                    flash('Your account has been deleted successfully.', 'success')
                    return redirect(url_for('main.index'))
                    
                except Exception as e:
                    logger.error(f"Error deleting account: {str(e)}")
                    flash('An error occurred while deleting your account. Please try again.', 'danger')
            else:
                flash('Please type DELETE to confirm account deletion.', 'danger')
        
        return render_template('unsubscribe.html')
    else:
        # User not logged in, redirect to login
        flash('Please log in to manage your account.', 'info')
        return redirect(url_for('main.login'))

@main.route('/events')
def events():
    """Display recent events"""
    page = request.args.get('page', 1, type=int)
    events = Event.query.order_by(Event.timestamp.desc()).paginate(
        page=page, per_page=10, error_out=False)
    return render_template('events.html', events=events)

@main.route('/api/events')
def api_events():
    """API endpoint to get recent events as JSON"""
    days = request.args.get('days', 7, type=int)
    limit = request.args.get('limit', 50, type=int)
    
    # Cap limit at 100
    if limit > 100:
        limit = 100
        
    recent_events = Event.query.order_by(Event.timestamp.desc()).limit(limit).all()
    
    events_json = []
    for event in recent_events:
        events_json.append({
            'id': event.id,
            'event_id': event.event_id,
            'source': event.source,
            'event_type': event.event_type,
            'severity': event.severity,
            'location': event.location,
            'description': event.description,
            'timestamp': event.timestamp.isoformat()
        })
        
    return jsonify(events_json)

# Helper functions
def is_valid_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email)

def is_valid_phone(phone):
    """Validate phone number format"""
    # Remove all non-digit characters except plus
    cleaned = re.sub(r'[^\d+]', '', phone)
    # Check if it starts with + and has proper length
    return cleaned.startswith('+') and 8 <= len(cleaned) <= 15

def is_valid_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    
    return has_upper and has_lower and has_digit

@main.route('/authorize')
def authorize():
    """
    Step 1: Redirect the user to Google's OAuth 2.0 server
    """
    flow = Flow.from_client_secrets_file(
        current_app.config['GMAIL_API_CREDENTIALS'],           # path to your client_secret.json
        scopes=current_app.config['GMAIL_API_SCOPES'],
        redirect_uri='http://127.0.0.1:5000/oauth2callback',
    )
    auth_url, state = flow.authorization_url(
        access_type='offline',       # to get a refresh token
        prompt='consent'             # force re-consent so you actually get a refresh token
    )
    session['oauth_state'] = state
    return redirect(auth_url)

@main.route('/oauth2callback')
def oauth2callback():
    """
    Step 2: Exchange code for credentials and save them
    """
    state = session.pop('oauth_state', None)
    flow = Flow.from_client_secrets_file(
        current_app.config['GMAIL_API_CREDENTIALS'],
        scopes=current_app.config['GMAIL_API_SCOPES'],
        state=state,
        redirect_uri=url_for('main.oauth2callback', _external=True)
    )
    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials
    
    # Persist to disk for reuse
    with open(current_app.config['GMAIL_API_TOKEN'], 'w') as token_file:
        token_file.write(creds.to_json())

    return redirect(url_for('main.index'))

@main.route('/admin/power-outage-emails', methods=['GET', 'POST'])
@login_required
def power_outage_email_admin():
    """Admin interface for power outage email forwarding"""
    # You might want to add admin role checking here
    # For now, any logged-in user can access this
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'check_now':
            hours_back = int(request.form.get('hours_back', 1))
            
            try:
                from app.email_forwarder import GmailForwarder
                
                forwarder = GmailForwarder()
                if forwarder.service is None:
                    flash('Gmail authentication failed. Please ensure you have authorized Gmail access at http://127.0.0.1:5000/authorize', 'danger')
                else:
                    success = forwarder.check_and_forward_power_outage_alerts(
                        hours_back=hours_back
                    )
                    
                    if success:
                        flash(f'Power outage email check completed successfully! Checked last {hours_back} hour(s).', 'success')
                    else:
                        flash('Power outage email check failed. Check logs for details.', 'danger')
                        
            except Exception as e:
                logger.error(f"Error in manual power outage email check: {e}")
                flash(f'Error occurred: {str(e)}', 'danger')
        
        return redirect(url_for('main.power_outage_email_admin'))
    
    # GET request - show admin page
    # Get recent power outage email events
    recent_events = Event.query.filter_by(source='POWEROUTAGE_EMAIL').order_by(Event.timestamp.desc()).limit(10).all()
    
    return render_template('admin/power_outage_emails.html', events=recent_events)

@main.route('/admin/gmail-status')
@login_required
def gmail_status():
    """Check Gmail API authentication status"""
    try:
        from app.email_forwarder import GmailForwarder
        
        forwarder = GmailForwarder()
        
        if forwarder.service is None:
            status = {
                'authenticated': False,
                'message': 'Gmail API not authenticated. Please visit http://127.0.0.1:5000/authorize to grant access.',
                'error': True
            }
        else:
            # Try to make a simple API call to verify authentication
            try:
                profile = forwarder.service.users().getProfile(userId='me').execute()
                status = {
                    'authenticated': True,
                    'message': f'Gmail API authenticated successfully. Email: {profile.get("emailAddress", "Unknown")}',
                    'email': profile.get('emailAddress'),
                    'error': False
                }
            except Exception as e:
                status = {
                    'authenticated': False,
                    'message': f'Gmail API authentication error: {str(e)}',
                    'error': True
                }
        
        return jsonify(status)
        
    except Exception as e:
        return jsonify({
            'authenticated': False,
            'message': f'Error checking Gmail status: {str(e)}',
            'error': True
        })

@main.route('/favicon.ico')
def favicon():
    return send_from_directory(current_app.static_folder, 'bell_icon.ico')

@main.route('/preview-sms-stop-template')
def preview():
    return render_template("sms_stop_handler.html")  # This file should be inside templates/