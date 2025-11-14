"""Flask Employee Portal - Role-based access system"""
from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file

from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_file, make_response
from flask.typing import ResponseReturnValue
from flask.wrappers import Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
  LoginManager, UserMixin, login_user, logout_user, login_required, current_user
)
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone, date, timedelta
from typing import Dict, Optional, Union, List, Any, Tuple, Callable, TypeVar, cast, TYPE_CHECKING
from typing_extensions import ParamSpec
from pydantic import BaseModel, Field, EmailStr, field_validator, ValidationError
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import os
import json
import re
import logging
import secrets
from functools import wraps
from config import CONFIG
import qrcode
from io import BytesIO
import base64

# Type variables for decorator typing
P = ParamSpec('P')
T = TypeVar('T')

# Configure application logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask application and configure security settings
app = Flask(__name__)

# Require SECRET_KEY to be set in environment
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable must be set. Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'")
app.config['SECRET_KEY'] = SECRET_KEY

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

COMPANY_NAME = CONFIG.get('COMPANY_NAME', 'Employee Portal')
app.config['COMPANY_NAME'] = COMPANY_NAME
app.jinja_env.globals['CONFIG'] = CONFIG
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# Security settings - adjust SESSION_COOKIE_SECURE based on environment
IS_PRODUCTION = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_SECURE'] = IS_PRODUCTION  # True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600
app.config['WTF_CSRF_TIME_LIMIT'] = None
app.config['REMEMBER_COOKIE_SECURE'] = IS_PRODUCTION

# Rate limiting configuration
app.config['RATELIMIT_STORAGE_URL'] = 'memory://'
app.config['RATELIMIT_STRATEGY'] = 'fixed-window'

# Initialize database, CSRF protection, and login manager
db: SQLAlchemy = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Initialize Flask-Mail for automated emails
app.config['MAIL_SERVER'] = CONFIG.get('MAIL_SERVER', 'smtp.office365.com')
app.config['MAIL_PORT'] = CONFIG.get('MAIL_PORT', 587)
app.config['MAIL_USE_TLS'] = CONFIG.get('MAIL_USE_TLS', True)
app.config['MAIL_USERNAME'] = CONFIG.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = CONFIG.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = CONFIG.get('MAIL_DEFAULT_SENDER', '')
mail = Mail(app)


# Add security and cache control headers to all responses
@app.after_request
def add_header(response: Response) -> Response:
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; frame-ancestors 'self'"
    return response


# Pydantic models for type-safe input validation
class TicketCreate(BaseModel):

    item: str = Field(..., min_length=1, max_length=200, description="Ticket item name")
    reason: str = Field(..., min_length=10, max_length=5000, description="Ticket reason/description")
    employee_id: Optional[int] = Field(None, ge=1, description="Employee ID for admin-created tickets")

    @field_validator('item')
    @classmethod
    def validate_item(cls, v: str) -> str:
        """Validate and sanitize ticket item field"""
        v = v.strip()
        if not v:
            raise ValueError('Item cannot be empty')
        # Remove any HTML tags for security
        v = re.sub(r'<[^>]*>', '', v)
        return v

    @field_validator('reason')
    @classmethod
    def validate_reason(cls, v: str) -> str:
        """Validate and sanitize ticket reason field"""
        v = v.strip()
        if len(v) < 10:
            raise ValueError('Reason must be at least 10 characters')
        # Remove any HTML tags for security
        v = re.sub(r'<[^>]*>', '', v)
        return v


class ServiceRequestCreate(BaseModel):
    """Type-safe service request creation model"""
    category: str = Field(..., min_length=1, max_length=50, description="Request category: DevOps or Developer")
    request_type: str = Field(..., min_length=1, max_length=100, description="Type of request")
    details: Optional[str] = Field(None, max_length=5000, description="Optional additional details")
    employee_id: Optional[int] = Field(None, ge=1, description="Employee ID for admin-created requests")

    @field_validator('category')
    @classmethod
    def validate_category(cls, v: str) -> str:
        """Validate category is one of allowed values"""
        v = v.strip()
        if v not in ['DevOps', 'Developer']:
            raise ValueError('Category must be either DevOps or Developer')
        return v

    @field_validator('request_type')
    @classmethod
    def validate_request_type(cls, v: str) -> str:
        """Validate and sanitize request type"""
        v = v.strip()
        if not v:
            raise ValueError('Request type cannot be empty')
        # Remove any HTML tags for security
        v = re.sub(r'<[^>]*>', '', v)
        return v

    @field_validator('details')
    @classmethod
    def validate_details(cls, v: Optional[str]) -> Optional[str]:
        """Validate and sanitize details field"""
        if v:
            v = v.strip()
            # Remove any HTML tags for security
            v = re.sub(r'<[^>]*>', '', v)
            return v if v else None
        return v


class UserDetailsUpdate(BaseModel):
    """Type-safe employee profile update model"""
    phone: Optional[str] = Field(None, max_length=50)
    email: Optional[EmailStr] = None
    laptop: Optional[str] = Field(None, max_length=200)
    charger: Optional[str] = Field(None, max_length=200)
    keyboard: Optional[str] = Field(None, max_length=200)
    mouse: Optional[str] = Field(None, max_length=200)
    headset: Optional[str] = Field(None, max_length=200)
    more_device: Optional[str] = Field(None, max_length=200, description="Additional mobile devices")
    bags: Optional[str] = Field(None, max_length=200, description="Office-allotted bags")
    vpn_access: bool = False
    email_access: bool = False
    biometric_access: bool = False
    floor_level_1: bool = False
    floor_level_2: bool = False

    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v: Optional[str]) -> Optional[str]:
        """Validate and sanitize phone number"""
        if v:
            v = v.strip()
            # Remove non-phone characters
            cleaned = re.sub(r'[^\d\+\-\(\)\s]', '', v)
            if len(cleaned) < 10:
                raise ValueError('Phone number must be at least 10 digits')
            return cleaned
        return v

    @field_validator('laptop', 'charger', 'keyboard', 'mouse', 'headset', 'more_device', 'bags')
    @classmethod
    def validate_assets(cls, v: Optional[str]) -> Optional[str]:
        """Validate and sanitize asset fields"""
        if v:
            v = v.strip()
            # Remove any HTML tags for security
            v = re.sub(r'<[^>]*>', '', v)
            return v
        return v


class LoginCredentials(BaseModel):

    username: str = Field(..., min_length=1, max_length=80)
    password: str = Field(..., min_length=8)

    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username format"""
        v = v.strip()
        if not re.match(r'^[a-zA-Z0-9._-]+$', v):
            raise ValueError('Username can only contain letters, numbers, dots, underscores, and hyphens')
        return v
    
    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password strength"""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one number')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v


class AssetCreate(BaseModel):
    """Type-safe asset creation model"""
    asset_id: str = Field(..., min_length=1, max_length=100)
    asset_type: str = Field(..., min_length=1, max_length=50)
    brand: Optional[str] = Field(None, max_length=100)
    model: Optional[str] = Field(None, max_length=100)
    serial_number: Optional[str] = Field(None, max_length=100)
    purchase_date: Optional[str] = None
    warranty_expiry: Optional[str] = None
    notes: Optional[str] = Field(None, max_length=1000)

    @field_validator('asset_id', 'asset_type')
    @classmethod
    def validate_required_fields(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError('This field cannot be empty')
        return re.sub(r'<[^>]*>', '', v)


class OnboardingCreate(BaseModel):
    """Type-safe onboarding creation model"""
    full_name: str = Field(..., min_length=1, max_length=200)
    personal_email: Optional[EmailStr] = None
    phone: Optional[str] = Field(None, max_length=50)
    emergency_contact_name: Optional[str] = Field(None, max_length=200)
    emergency_contact_phone: Optional[str] = Field(None, max_length=50)
    address: Optional[str] = Field(None, max_length=500)
    date_of_birth: Optional[str] = None
    joining_date: str
    role: str = Field(..., min_length=1, max_length=100)
    department: str = Field(..., min_length=1, max_length=100)
    reporting_manager: Optional[str] = Field(None, max_length=200)
    work_location: Optional[str] = Field(None, max_length=200)
    employment_type: Optional[str] = Field(None, max_length=50)


class ExitCreate(BaseModel):
    """Type-safe exit process creation model"""
    exit_date: str
    last_working_day: str
    reason: Optional[str] = Field(None, max_length=100)
    exit_type: Optional[str] = Field(None, max_length=50)
    notes: Optional[str] = Field(None, max_length=1000)


# Security utility functions
def sanitize_input(input_str: str, max_length: int = 1000) -> str:
    """Remove HTML tags and limit input length for security"""
    if not input_str:
        return ""
    # Remove HTML tags
    cleaned = re.sub(r'<[^>]*>', '', input_str)
    # Remove script tags as additional security layer
    cleaned = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', cleaned, flags=re.IGNORECASE)
    return cleaned[:max_length].strip()


def validate_ticket_status(status: str) -> bool:
    allowed = set(CONFIG.get('TICKET_STATUSES', []))
    return status in allowed


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password strength and return (is_valid, error_message)
    Checks for common weak passwords and enforces complexity requirements
    """
    # Common weak passwords to reject
    weak_passwords = {
        'password', 'password123', '12345678', 'qwerty123', 'admin123',
        'letmein', 'welcome123', 'monkey123', '1q2w3e4r', 'password1',
        'abc123456', 'password!', 'admin@123', 'welcome@123', 'password1234',
        '123456789012', 'qwertyuiop12', 'admin@123456'
    }
    
    if password.lower() in weak_passwords:
        return False, 'This password is too common. Please choose a stronger password'
    
    if len(password) < 8:
        return False, 'Password must be at least 8 characters long'
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter'
    if not re.search(r'[a-z]', password):
        return False, 'Password must contain at least one lowercase letter'
    if not re.search(r'\d', password):
        return False, 'Password must contain at least one number'
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, 'Password must contain at least one special character'
    return True, ''


def generate_unique_asset_id() -> str:
    """Generate a cryptographically secure unique asset ID using UUID"""
    import uuid
    # Use UUID4 for guaranteed uniqueness, take first 7 chars and ensure it's numeric
    # Alternative: use a more robust approach with database sequence
    max_attempts = 10
    
    for _ in range(max_attempts):
        # Generate a random 7-digit number
        asset_id = str(secrets.randbelow(9000000) + 1000000)
        
        # Use database-level check with row locking to prevent race condition
        try:
            # Check if it already exists with a lock
            existing = db.session.query(Asset.id).filter_by(asset_id=asset_id).with_for_update().first()
            if not existing:
                return asset_id
        except Exception as e:
            logger.warning(f"Error checking asset ID uniqueness: {e}")
            continue
    
    # Fallback: use timestamp-based ID with random suffix
    import time
    timestamp = str(int(time.time() * 1000))[-7:]
    return timestamp


# QR Code generation utility
def generate_qr_code(data: str) -> str:
    """Generate QR code and return as base64 encoded string"""
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_base64}"


# Email sending utilities (using Any type to avoid forward reference issues)
def send_welcome_email(employee: Any, onboarding: Any) -> bool:
    """Send welcome email to new employee"""
    try:
        if not employee.email:
            logger.warning(f"Cannot send welcome email to {employee.username}: no email address")
            return False
            
        msg = Message(
            subject=f"Welcome to {COMPANY_NAME}!",
            recipients=[employee.email],
            html=f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #007aff;">Welcome to {COMPANY_NAME}!</h2>
                    <p>Dear {onboarding.full_name},</p>
                    <p>We are excited to have you join our team as <strong>{onboarding.role}</strong> in the <strong>{onboarding.department}</strong> department.</p>
                    <p><strong>Your Details:</strong></p>
                    <ul>
                        <li>Username: {employee.username}</li>
                        <li>Department: {onboarding.department}</li>
                        <li>Role: {onboarding.role}</li>
                        <li>Joining Date: {onboarding.joining_date.strftime('%B %d, %Y') if onboarding.joining_date else 'N/A'}</li>
                    </ul>
                    <p>Please log in to the employee portal to complete your profile and access company resources.</p>
                    <p>If you have any questions, please don't hesitate to reach out to HR.</p>
                    <p>Best regards,<br>{COMPANY_NAME} Team</p>
                </div>
            </body>
            </html>
            """
        )
        mail.send(msg)
        logger.info(f"Welcome email sent to {employee.email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send welcome email to {employee.email}: {e}")
        return False


def send_birthday_email(employee: Any) -> bool:
    """Send birthday wishes email"""
    try:
        if not employee.email:
            return False
            
        msg = Message(
            subject=f"Happy Birthday from {COMPANY_NAME}! 🎉",
            recipients=[employee.email],
            html=f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; text-align: center;">
                    <h1 style="color: #007aff;">🎂 Happy Birthday, {employee.username}! 🎉</h1>
                    <p style="font-size: 18px;">Wishing you a wonderful day filled with joy and happiness!</p>
                    <p>Thank you for being a valuable member of our team.</p>
                    <p style="margin-top: 30px;">Best wishes,<br><strong>{COMPANY_NAME} Team</strong></p>
                </div>
            </body>
            </html>
            """
        )
        mail.send(msg)
        logger.info(f"Birthday email sent to {employee.email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send birthday email to {employee.email}: {e}")
        return False


def send_anniversary_email(employee: Any, years: int) -> bool:
    """Send work anniversary email"""
    try:
        if not employee.email:
            return False
            
        msg = Message(
            subject=f"Happy Work Anniversary from {COMPANY_NAME}! 🎊",
            recipients=[employee.email],
            html=f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; text-align: center;">
                    <h1 style="color: #007aff;">🎊 Congratulations on {years} Year{'s' if years > 1 else ''} with Us! 🎊</h1>
                    <p style="font-size: 18px;">Dear {employee.username},</p>
                    <p>Today marks {years} year{'s' if years > 1 else ''} since you joined {COMPANY_NAME}!</p>
                    <p>Thank you for your dedication, hard work, and valuable contributions to our team.</p>
                    <p>We look forward to many more successful years together!</p>
                    <p style="margin-top: 30px;">Best regards,<br><strong>{COMPANY_NAME} Team</strong></p>
                </div>
            </body>
            </html>
            """
        )
        mail.send(msg)
        logger.info(f"Anniversary email sent to {employee.email} for {years} years")
        return True
    except Exception as e:
        logger.error(f"Failed to send anniversary email to {employee.email}: {e}")
        return False


# Automated email scheduler functions
def check_birthdays() -> None:
    """Check for employee birthdays and send emails"""
    with app.app_context():
        try:
            today = date.today()
            onboardings = Onboarding.query.filter(Onboarding.status == 'Completed').all()
            
            for onboarding in onboardings:
                if onboarding.date_of_birth:
                    if (onboarding.date_of_birth.month == today.month and 
                        onboarding.date_of_birth.day == today.day):
                        employee = onboarding.employee
                        if employee and employee.email:
                            send_birthday_email(employee)
                            logger.info(f"Birthday email sent to {employee.username}")
        except Exception as e:
            logger.error(f"Error checking birthdays: {e}")


def check_anniversaries() -> None:
    """Check for work anniversaries and send emails"""
    with app.app_context():
        try:
            today = date.today()
            onboardings = Onboarding.query.filter(Onboarding.status == 'Completed').all()
            
            for onboarding in onboardings:
                if onboarding.joining_date:
                    if (onboarding.joining_date.month == today.month and 
                        onboarding.joining_date.day == today.day):
                        years = today.year - onboarding.joining_date.year
                        if years > 0:  # At least 1 year
                            employee = onboarding.employee
                            if employee and employee.email:
                                send_anniversary_email(employee, years)
                                logger.info(f"Anniversary email sent to {employee.username} for {years} years")
        except Exception as e:
            logger.error(f"Error checking anniversaries: {e}")


# Custom decorator to restrict routes to admin users only
def admin_required(f: Callable[P, T]) -> Callable[P, T]:
    """Custom decorator to restrict routes to admin users only"""
    @wraps(f)
    def decorated_function(*args: P.args, **kwargs: P.kwargs) -> T:
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
            username = getattr(current_user, 'username', 'anonymous') if current_user.is_authenticated else 'anonymous'
            logger.warning(f"Unauthorized access attempt to admin route by user: {username}")
            abort(403)
        return f(*args, **kwargs)
    return cast(Callable[P, T], decorated_function)


TICKET_GROUPS = CONFIG.get('TICKET_GROUPS', {})
SERVICE_REQUEST_TYPES = CONFIG.get('SERVICE_REQUEST_TYPES', {})


# Database models
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    __allow_unmapped__ = True

    id: Any = db.Column(db.Integer, primary_key=True)
    username: Any = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash: Any = db.Column(db.String(200), nullable=False)
    is_admin: Any = db.Column(db.Boolean, default=False)
    
    name: Any = db.Column(db.String(150))
    department: Any = db.Column(db.String(100))

    phone: Any = db.Column(db.String(50))
    email: Any = db.Column(db.String(120), index=True)
    laptop: Any = db.Column(db.String(200))
    charger: Any = db.Column(db.String(200))
    keyboard: Any = db.Column(db.String(200))
    mouse: Any = db.Column(db.String(200))
    headset: Any = db.Column(db.String(200))
    more_device: Any = db.Column(db.String(200))
    bags: Any = db.Column(db.String(200))

    access_json: Any = db.Column(db.Text, default='{}')
    details_filled: Any = db.Column(db.Boolean, default=False)
    date_of_birth: Any = db.Column(db.Date)
    joining_date: Any = db.Column(db.Date)

    def set_password(self, pw: str) -> None:
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)

    def get_access(self) -> Dict[str, bool]:
        """Deserialize JSON access permissions"""
        try:
            return json.loads(self.access_json or '{}')
        except Exception:
            return {}

    def set_access(self, d: Optional[Dict[str, bool]]) -> None:
        """Serialize access permissions to JSON"""
        self.access_json = json.dumps(d or {})


class Ticket(db.Model):
    __tablename__ = 'ticket'
    __allow_unmapped__ = True

    id: Any = db.Column(db.Integer, primary_key=True)
    employee_id: Any = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    item: Any = db.Column(db.String(200), nullable=False)
    reason: Any = db.Column(db.Text, nullable=False)
    status: Any = db.Column(db.String(50), default='Pending')
    created_at: Any = db.Column(db.DateTime, server_default=db.func.now())
    updated_at: Any = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    employee: Any = db.relationship('User', backref='tickets')


class ServiceRequest(db.Model):
    """Model for service requests (DevOps and Developer requests)"""
    __tablename__ = 'service_request'
    __allow_unmapped__ = True

    id: Any = db.Column(db.Integer, primary_key=True)
    employee_id: Any = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    category: Any = db.Column(db.String(50), nullable=False)  # 'DevOps' or 'Developer'
    request_type: Any = db.Column(db.String(100), nullable=False)  # e.g., 'Add Port', 'GitHub Access Request'
    details: Any = db.Column(db.Text)  # Optional additional details
    status: Any = db.Column(db.String(50), default='Pending')  # Pending, Approved, Rejected, Revoked
    created_at: Any = db.Column(db.DateTime, server_default=db.func.now())
    updated_at: Any = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    employee: Any = db.relationship('User', backref='service_requests')


class GitHubRepoAccess(db.Model):
    """Model for tracking GitHub repository access for employees"""
    __tablename__ = 'github_repo_access'
    __allow_unmapped__ = True

    id: Any = db.Column(db.Integer, primary_key=True)
    employee_id: Any = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    repo_name: Any = db.Column(db.String(200), nullable=False)
    access_granted_date: Any = db.Column(db.DateTime, server_default=db.func.now())
    access_revoked_date: Any = db.Column(db.DateTime, nullable=True)
    is_active: Any = db.Column(db.Boolean, default=True)
    created_at: Any = db.Column(db.DateTime, server_default=db.func.now())
    updated_at: Any = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    employee: Any = db.relationship('User', backref='github_accesses')


class Asset(db.Model):
    """Model for tracking company assets with QR codes"""
    __tablename__ = 'asset'
    __allow_unmapped__ = True

    id: Any = db.Column(db.Integer, primary_key=True)
    asset_id: Any = db.Column(db.String(100), unique=True, nullable=False, index=True)
    asset_type: Any = db.Column(db.String(50), nullable=False)
    brand: Any = db.Column(db.String(100))
    model: Any = db.Column(db.String(100))
    serial_number: Any = db.Column(db.String(100))
    purchase_date: Any = db.Column(db.Date)
    warranty_expiry: Any = db.Column(db.Date)
    status: Any = db.Column(db.String(50), default='Available')  # Available, Assigned, Maintenance, Retired
    assigned_to: Any = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    assigned_date: Any = db.Column(db.DateTime)
    notes: Any = db.Column(db.Text)
    qr_code: Any = db.Column(db.Text)  # Base64 encoded QR code image
    created_at: Any = db.Column(db.DateTime, server_default=db.func.now())
    updated_at: Any = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    employee: Any = db.relationship('User', backref='assigned_assets', foreign_keys=[assigned_to])


class Onboarding(db.Model):
    """Model for employee onboarding process"""
    __tablename__ = 'onboarding'
    __allow_unmapped__ = True

    id: Any = db.Column(db.Integer, primary_key=True)
    employee_id: Any = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    full_name: Any = db.Column(db.String(200), nullable=False)
    personal_email: Any = db.Column(db.String(120))
    phone: Any = db.Column(db.String(50))
    emergency_contact_name: Any = db.Column(db.String(200))
    emergency_contact_phone: Any = db.Column(db.String(50))
    address: Any = db.Column(db.Text)
    date_of_birth: Any = db.Column(db.Date)
    joining_date: Any = db.Column(db.Date, nullable=False)
    role: Any = db.Column(db.String(100), nullable=False)
    department: Any = db.Column(db.String(100), nullable=False)
    reporting_manager: Any = db.Column(db.String(200))
    work_location: Any = db.Column(db.String(200))
    employment_type: Any = db.Column(db.String(50))  # Full-time, Part-time, Contract
    
    # Assigned devices/assets (JSON array of asset IDs)
    assigned_assets_json: Any = db.Column(db.Text, default='[]')
    
    # Onboarding status
    status: Any = db.Column(db.String(50), default='Pending')  # Pending, In Progress, Completed
    welcome_email_sent: Any = db.Column(db.Boolean, default=False)
    completed_date: Any = db.Column(db.DateTime)
    
    created_at: Any = db.Column(db.DateTime, server_default=db.func.now())
    updated_at: Any = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    employee: Any = db.relationship('User', backref='onboarding_record')

    def get_assigned_assets(self) -> List[str]:
        """Deserialize assigned assets"""
        try:
            return json.loads(self.assigned_assets_json or '[]')
        except Exception:
            return []

    def set_assigned_assets(self, assets: List[str]) -> None:
        """Serialize assigned assets"""
        self.assigned_assets_json = json.dumps(assets or [])


class EmployeeExit(db.Model):
    """Model for employee exit/offboarding process"""
    __tablename__ = 'employee_exit'
    __allow_unmapped__ = True

    id: Any = db.Column(db.Integer, primary_key=True)
    employee_id: Any = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    exit_date: Any = db.Column(db.Date, nullable=False)
    last_working_day: Any = db.Column(db.Date, nullable=False)
    reason: Any = db.Column(db.String(100))  # Resignation, Termination, Retirement, etc.
    exit_type: Any = db.Column(db.String(50))  # Voluntary, Involuntary
    
    # Asset return tracking
    assets_returned: Any = db.Column(db.Boolean, default=False)
    assets_return_date: Any = db.Column(db.DateTime)
    assets_notes: Any = db.Column(db.Text)
    
    # Access revocation tracking
    email_access_revoked: Any = db.Column(db.Boolean, default=False)
    vpn_access_revoked: Any = db.Column(db.Boolean, default=False)
    system_access_revoked: Any = db.Column(db.Boolean, default=False)
    building_access_revoked: Any = db.Column(db.Boolean, default=False)
    
    # Exit interview and clearance
    exit_interview_completed: Any = db.Column(db.Boolean, default=False)
    exit_interview_date: Any = db.Column(db.DateTime)
    clearance_certificate_issued: Any = db.Column(db.Boolean, default=False)
    
    # Overall status
    status: Any = db.Column(db.String(50), default='Initiated')  # Initiated, In Progress, Completed
    completed_date: Any = db.Column(db.DateTime)
    notes: Any = db.Column(db.Text)
    
    created_at: Any = db.Column(db.DateTime, server_default=db.func.now())
    updated_at: Any = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    employee: Any = db.relationship('User', backref='exit_record')


# Flask-Login user loader callback
@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    return db.session.get(User, int(user_id))


# Global error handlers
@app.errorhandler(403)
def forbidden(e: Exception) -> Tuple[str, int]:
    """Handle 403 Forbidden errors"""
    logger.warning(f"403 Forbidden: {request.url}")
    return render_template('errors/403.html'), 403


@app.errorhandler(404)
def not_found(e: Exception) -> Tuple[str, int]:
    """Handle 404 Not Found errors"""
    logger.info(f"404 Not Found: {request.url}")
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_error(e: Exception) -> Tuple[str, int]:
    """Handle 500 Internal Server errors"""
    db.session.rollback()
    logger.error(f"500 Internal Server Error: {str(e)}")
    return render_template('errors/500.html'), 500


@app.errorhandler(429)
def ratelimit_handler(e: Exception) -> Tuple[str, int]:
    """Handle rate limit exceeded errors"""
    logger.warning(f"Rate limit exceeded: {request.remote_addr}")
    return render_template('errors/429.html'), 429


# Application routes
@app.route("/")
def index():
    """Redirect authenticated users to their respective dashboard"""
    if current_user.is_authenticated:
        return redirect(url_for("admin_dashboard" if current_user.is_admin else "employee_dashboard_redirect"))
    return redirect(url_for("login"))


# Authentication routes
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login() -> ResponseReturnValue:
    """Handle user authentication with role-based redirection"""
    admins: List[str] = [u.username for u in User.query.filter_by(is_admin=True).all()]
    employees: List[str] = [u.username for u in User.query.filter_by(is_admin=False).all()]
    
    # Get unique departments for employees using select
    from sqlalchemy import select, distinct
    stmt = select(distinct(User.department)).where(User.is_admin == False, User.department.isnot(None))
    departments_query = db.session.execute(stmt).scalars().all()
    departments: List[str] = sorted([d for d in departments_query if d])
    
    # Create department mapping for employees
    employee_departments: Dict[str, List[str]] = {}
    for emp in User.query.filter_by(is_admin=False).all():
        if emp.department:
            if emp.department not in employee_departments:
                employee_departments[emp.department] = []
            employee_departments[emp.department].append(emp.username)

    if request.method == "POST":
        try:
            # Validate login credentials with Pydantic
            credentials = LoginCredentials(
                username=request.form.get("username", ""),
                password=request.form.get("password", "")
            )

            user_query = User.query.filter_by(username=credentials.username).first()
            user: Optional[User] = cast(Optional[User], user_query)
            if not user:
                logger.warning(f"Failed login attempt for non-existent user: {credentials.username}")
                flash("Invalid username or password", "error")
                return redirect(url_for("login"))

            if not user.check_password(credentials.password):
                logger.warning(f"Failed login attempt for user: {credentials.username}")
                flash("Invalid username or password", "error")
                return redirect(url_for("login"))

            login_user(user)
            # Regenerate session to prevent session fixation attacks
            from flask import session
            session.permanent = True
            logger.info(f"Successful login for user: {user.username}")
            flash(f"Welcome, {user.username}!", "success")

            if user.is_admin:
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("employee_dashboard_redirect"))

        except ValidationError as e:
            logger.error(f"Validation error during login: {e}")
            flash("Invalid username or password format", "error")
            return redirect(url_for("login"))
        except Exception as e:
            logger.error(f"Unexpected error during login: {e}")
            flash("An error occurred. Please try again.", "error")
            return redirect(url_for("login"))

    return render_template("login.html", 
                         admins=admins, 
                         employees=employees, 
                         departments=departments,
                         employee_departments=employee_departments)


@app.route("/logout")
@login_required
def logout() -> ResponseReturnValue:
    logout_user()
    flash("You’ve been logged out successfully.", "success")
    return redirect(url_for("login"))


@app.route('/employee/dashboard')
@login_required
def employee_dashboard_redirect() -> ResponseReturnValue:
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('employee_details'))


# Employee area routes
@app.route('/employee/details', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per minute")
def employee_details() -> ResponseReturnValue:
    """Employee profile management with one-time edit restriction"""
    if current_user.is_admin:
        flash('Admins cannot use employee details view', 'error')
        return redirect(url_for('admin_dashboard'))

    user = current_user

    # One-time editable: employees can only fill details once
    if request.method == 'POST' and not user.details_filled:
        try:
            # Validate employee details with Pydantic
            details = UserDetailsUpdate(
                phone=request.form.get('phone'),
                email=request.form.get('email'),
                laptop=request.form.get('laptop'),
                charger=request.form.get('charger'),
                keyboard=request.form.get('keyboard'),
                mouse=request.form.get('mouse'),
                headset=request.form.get('headset'),
                more_device=request.form.get('more_device'),
                bags=request.form.get('bags'),
                vpn_access=bool(request.form.get('vpn_access')),
                email_access=bool(request.form.get('email_access')),
                biometric_access=bool(request.form.get('biometric_access')),
                floor_level_1=bool(request.form.get('floor_level_1')),
                floor_level_2=bool(request.form.get('floor_level_2'))
            )

            # Update user profile with validated details
            user.phone = details.phone
            user.email = details.email
            user.laptop = details.laptop
            user.charger = details.charger
            user.keyboard = details.keyboard
            user.mouse = details.mouse
            user.headset = details.headset
            user.more_device = details.more_device
            user.bags = details.bags

            access = {
                'vpn': details.vpn_access,
                'email': details.email_access,
                'biometric': details.biometric_access,
                'floor_level_1': details.floor_level_1,
                'floor_level_2': details.floor_level_2
            }
            user.set_access(access)
            user.details_filled = True  # Lock details from further edits
            db.session.commit()
            logger.info(f"User {user.username} updated their details")
            flash('Details saved. You will not be able to edit them again.', 'success')
            return redirect(url_for('employee_details'))

        except ValidationError as e:
            logger.error(f"Validation error updating details: {e}")
            errors = e.errors()
            for error in errors:
                flash(f"{error['loc'][0]}: {error['msg']}", 'error')
            return redirect(url_for('employee_details'))
        except Exception as e:
            logger.error(f"Error updating details: {e}")
            flash('An error occurred while saving details', 'error')
            return redirect(url_for('employee_details'))

    return render_template('pages/employee/details.html', user=user)


@app.route('/employee/raise', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute")
def employee_raise() -> ResponseReturnValue:
    if current_user.is_admin:
        flash('Admins cannot raise employee tickets here', 'error')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        try:
            # Validate ticket data with Pydantic
            ticket_data = TicketCreate(
                item=request.form.get('item', ''),
                reason=request.form.get('reason', ''),
                employee_id=current_user.id
            )

            ticket = Ticket(
                employee_id=current_user.id,
                item=ticket_data.item,
                reason=ticket_data.reason,
                status='Pending',
                created_at=datetime.now(timezone.utc)
            )
            db.session.add(ticket)
            db.session.commit()
            logger.info(f"Ticket {ticket.id} created successfully for employee {current_user.id}")
            flash('Ticket raised and is pending approval', 'success')
            return redirect(url_for('employee_raise'))

        except ValidationError as e:
            logger.error(f"Validation error creating ticket: {e}")
            errors = e.errors()
            for error in errors:
                flash(f"{error['loc'][0]}: {error['msg']}", 'error')
            return redirect(url_for('employee_raise'))
        except Exception as e:
            logger.error(f"Error creating ticket: {e}")
            flash('An error occurred. Please try again or contact support.', 'error')
            return redirect(url_for('employee_raise'))

    tickets: List[Ticket] = Ticket.query.filter_by(employee_id=current_user.id).order_by(Ticket.created_at.desc()).all()
    return render_template('pages/employee/raise_ticket.html', groups=TICKET_GROUPS, tickets=tickets)


@app.route('/employee/service-requests', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute")
def employee_service_requests() -> ResponseReturnValue:
    """Employee service requests page - handle DevOps and Developer requests"""
    if current_user.is_admin:
        flash('Admins cannot access employee service requests', 'error')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        try:
            # Validate service request data with Pydantic
            service_request_data = ServiceRequestCreate(
                category=request.form.get('category', ''),
                request_type=request.form.get('request_type', ''),
                details=request.form.get('details', ''),
                employee_id=current_user.id
            )

            service_request = ServiceRequest(
                employee_id=current_user.id,
                category=service_request_data.category,
                request_type=service_request_data.request_type,
                details=service_request_data.details,
                status='Pending',
                created_at=datetime.now(timezone.utc)
            )
            db.session.add(service_request)
            db.session.commit()
            logger.info(f"Service request {service_request.id} created successfully for employee {current_user.id}")
            flash('Service request submitted successfully and is pending approval', 'success')
            return redirect(url_for('employee_service_requests'))

        except ValidationError as e:
            logger.error(f"Validation error creating service request: {e}")
            errors = e.errors()
            for error in errors:
                flash(f"{error['loc'][0]}: {error['msg']}", 'error')
            return redirect(url_for('employee_service_requests'))
        except Exception as e:
            logger.error(f"Error creating service request: {e}")
            flash('An error occurred. Please try again or contact support.', 'error')
            return redirect(url_for('employee_service_requests'))

    # Get employee's service requests
    service_requests: List[ServiceRequest] = ServiceRequest.query.filter_by(employee_id=current_user.id).order_by(ServiceRequest.created_at.desc()).all()
    return render_template('pages/employee/service_requests.html', 
                         service_request_types=SERVICE_REQUEST_TYPES, 
                         service_requests=service_requests)


# Admin area routes
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard() -> str:
    """Display admin dashboard with system statistics"""
    from sqlalchemy import func, case
    
    # Optimize: Get all stats in a single query using aggregation
    total_employees = User.query.filter_by(is_admin=False).count()
    
    # Get ticket statistics in one query
    ticket_stats = db.session.query(
        func.count(Ticket.id).label('total'),
        func.sum(case((Ticket.status == 'Pending', 1), else_=0)).label('pending'),
        func.sum(case((Ticket.status == 'Approved', 1), else_=0)).label('approved'),
        func.sum(case((Ticket.status == 'Rejected', 1), else_=0)).label('rejected')
    ).first()

    stats = {
        'total_employees': total_employees,
        'total_tickets': ticket_stats.total or 0,
        'pending_tickets': ticket_stats.pending or 0,
        'approved_tickets': ticket_stats.approved or 0,
        'rejected_tickets': ticket_stats.rejected or 0
    }

    logger.info(f"Admin dashboard accessed by {current_user.username}")
    return render_template('pages/admin/dashboard.html', stats=stats)



@app.route('/admin/employees', methods=['GET'])
@login_required
@admin_required
def admin_employees_list() -> str:
    """Display list of all employees"""
    employees: List[User] = User.query.filter_by(is_admin=False).order_by(User.username).all()
    return render_template('pages/admin/employees.html', employees=employees)


@app.route('/admin/employees/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_employees_manage() -> ResponseReturnValue:
    if request.method == 'POST':
        uid = request.form.get('user_id')
        if not uid:
            flash('Select an employee before saving', 'error')
            return redirect(url_for('admin_employees_manage'))

        user = User.query.get(int(uid))
        if not user:
            flash('Employee not found', 'error')
            return redirect(url_for('admin_employees_manage'))

        try:
            # Validate employee details with Pydantic
            details = UserDetailsUpdate(
                phone=request.form.get('phone'),
                email=request.form.get('email'),
                laptop=request.form.get('laptop'),
                charger=request.form.get('charger'),
                keyboard=request.form.get('keyboard'),
                mouse=request.form.get('mouse'),
                headset=request.form.get('headset'),
                more_device=request.form.get('more_device'),
                bags=request.form.get('bags'),
                vpn_access=bool(request.form.get('vpn_access')),
                email_access=bool(request.form.get('email_access')),
                biometric_access=bool(request.form.get('biometric_access')),
                floor_level_1=bool(request.form.get('floor_level_1')),
                floor_level_2=bool(request.form.get('floor_level_2'))
            )
            # Update employee information
            user.phone = details.phone
            user.email = details.email
            user.laptop = details.laptop
            user.charger = details.charger
            user.keyboard = details.keyboard
            user.mouse = details.mouse
            user.headset = details.headset

            access = {
                'vpn': details.vpn_access,
                'email': details.email_access,
                'biometric': details.biometric_access
            }
            user.set_access(access)
            db.session.commit()
            logger.info(f"Admin {current_user.username} updated employee {user.username} via edit page")
            flash('Employee updated', 'success')
            return redirect(url_for('admin_employees_manage', employee=user.id))

        except ValidationError as e:
            logger.error(f"Validation error updating employee: {e}")
            errors = e.errors()
            for error in errors:
                flash(f"{error['loc'][0]}: {error['msg']}", 'error')
            return redirect(url_for('admin_employees_manage'))
        except Exception as e:
            logger.error(f"Error updating employee: {e}")
            flash('An error occurred', 'error')
            return redirect(url_for('admin_employees_manage'))

    employees: List[User] = User.query.filter_by(is_admin=False).order_by(User.username).all()
    
    # Get selected employee from query parameter
    selected_employee_id = request.args.get('employee', type=int)
    selected_employee = None
    if selected_employee_id:
        selected_employee = User.query.get(selected_employee_id)
    
    # Convert User objects to dictionaries for JSON serialization
    employees_data = []
    for emp in employees:
        employees_data.append({
            'id': emp.id,
            'username': emp.username,
            'phone': emp.phone or '',
            'email': emp.email or '',
            'laptop': emp.laptop or '',
            'charger': emp.charger or '',
            'keyboard': emp.keyboard or '',
            'mouse': emp.mouse or '',
            'headset': emp.headset or '',
            'access': emp.get_access()
        })
    
    return render_template('pages/admin/employees_manage.html', 
                         employees=employees, 
                         employees_data=employees_data,
                         selected_employee_id=selected_employee_id,
                         selected_employee=selected_employee)


@app.route('/admin/tickets', methods=['GET'])
@login_required
@admin_required
def admin_tickets() -> str:
    tickets: List[Ticket] = Ticket.query.order_by(Ticket.created_at.desc()).all()
    employees: List[User] = User.query.filter_by(is_admin=False).all()
    return render_template('pages/admin/tickets.html', tickets=tickets, groups=TICKET_GROUPS, employees=employees)


@app.route('/admin/raise', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_raise() -> ResponseReturnValue:
    employees: List[User] = User.query.filter_by(is_admin=False).all()
    if request.method == 'POST':
        try:
            emp_id_str = request.form.get('employee_id', '')
            if not emp_id_str:
                flash('Select employee', 'error')
                return redirect(url_for('admin_raise'))

            # Validate ticket data for admin-created tickets
            ticket_data = TicketCreate(
                item=request.form.get('item', ''),
                reason=request.form.get('reason', ''),
                employee_id=int(emp_id_str)
            )

            ticket = Ticket(
                employee_id=ticket_data.employee_id,
                item=ticket_data.item,
                reason=ticket_data.reason,
                status='Pending',
                created_at=datetime.now(timezone.utc)
            )
            db.session.add(ticket)
            db.session.commit()
            logger.info(f"Admin {current_user.username} created ticket {ticket.id} for employee {ticket.employee_id}")
            flash('Ticket raised for employee', 'success')
            return redirect(url_for('admin_tickets'))

        except ValidationError as e:
            logger.error(f"Validation error creating admin ticket: {e}")
            errors = e.errors()
            for error in errors:
                flash(f"{error['loc'][0]}: {error['msg']}", 'error')
            return redirect(url_for('admin_raise'))
        except ValueError:
            flash('Invalid employee ID', 'error')
            return redirect(url_for('admin_raise'))
        except Exception as e:
            logger.error(f"Error creating admin ticket: {e}")
            flash('An error occurred', 'error')
            return redirect(url_for('admin_raise'))

    return render_template('pages/admin/tickets.html',
                           tickets=Ticket.query.order_by(Ticket.created_at.desc()).all(),
                           groups=TICKET_GROUPS,
                           employees=employees)


@app.route('/admin/ticket/<int:ticket_id>/approve', methods=['POST'])
@login_required
@admin_required
@limiter.limit("30 per minute")
def admin_approve(ticket_id: int) -> ResponseReturnValue:
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        if not validate_ticket_status(ticket.status):
            flash("Invalid ticket status", "error")
            return redirect(url_for("admin_tickets"))
        
        # Validate status transition
        if ticket.status == "Approved":
            flash("Ticket is already approved", "warning")
            return redirect(url_for("admin_tickets"))
        if ticket.status == "Rejected":
            flash("Cannot approve a rejected ticket", "error")
            return redirect(url_for("admin_tickets"))

        ticket.status = "Approved"
        ticket.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        logger.info(f"Admin {current_user.username} approved ticket {ticket_id}")
        flash(f"Ticket {ticket_id} approved successfully", "success")
    except Exception as e:
        logger.error(f"Error approving ticket: {e}")
        flash("An error occurred. Please try again or contact support.", "error")

    return redirect(url_for("admin_tickets"))


@app.route('/admin/ticket/<int:ticket_id>/reject', methods=['POST'])
@login_required
@admin_required
@limiter.limit("30 per minute")
def admin_reject(ticket_id: int) -> ResponseReturnValue:
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        if not validate_ticket_status(ticket.status):
            flash("Invalid ticket status", "error")
            return redirect(url_for("admin_tickets"))
        
        # Validate status transition
        if ticket.status == "Rejected":
            flash("Ticket is already rejected", "warning")
            return redirect(url_for("admin_tickets"))
        if ticket.status == "Approved":
            flash("Cannot reject an approved ticket", "error")
            return redirect(url_for("admin_tickets"))

        ticket.status = "Rejected"
        ticket.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        logger.info(f"Admin {current_user.username} rejected ticket {ticket_id}")
        flash(f"Ticket {ticket_id} rejected successfully", "success")
    except Exception as e:
        logger.error(f"Error rejecting ticket: {e}")
        flash("An error occurred. Please try again or contact support.", "error")

    return redirect(url_for("admin_tickets"))


@app.route('/admin/service-requests', methods=['GET'])
@login_required
@admin_required
def admin_service_requests() -> str:
    """Display all service requests for admin review"""
    service_requests: List[ServiceRequest] = ServiceRequest.query.order_by(ServiceRequest.created_at.desc()).all()
    employees: List[User] = User.query.filter_by(is_admin=False).all()
    return render_template('pages/admin/service_requests.html', 
                         service_requests=service_requests,
                         service_request_types=SERVICE_REQUEST_TYPES,
                         employees=employees)


@app.route('/admin/service-request/<int:request_id>/approve', methods=['POST'])
@login_required
@admin_required
@limiter.limit("30 per minute")
def admin_approve_service_request(request_id: int) -> ResponseReturnValue:
    """Approve a service request"""
    try:
        service_request = ServiceRequest.query.get_or_404(request_id)
        service_request.status = "Approved"
        service_request.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        logger.info(f"Admin {current_user.username} approved service request {request_id}")
        flash(f"Service request #{request_id} approved successfully", "success")
    except Exception as e:
        logger.error(f"Error approving service request: {e}")
        flash("An error occurred while approving the service request", "error")

    return redirect(url_for("admin_service_requests"))


@app.route('/admin/service-request/<int:request_id>/reject', methods=['POST'])
@login_required
@admin_required
@limiter.limit("30 per minute")
def admin_reject_service_request(request_id: int) -> ResponseReturnValue:
    """Reject a service request"""
    try:
        service_request = ServiceRequest.query.get_or_404(request_id)
        service_request.status = "Rejected"
        service_request.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        logger.info(f"Admin {current_user.username} rejected service request {request_id}")
        flash(f"Service request #{request_id} rejected successfully", "success")
    except Exception as e:
        logger.error(f"Error rejecting service request: {e}")
        flash("An error occurred while rejecting the service request", "error")

    return redirect(url_for("admin_service_requests"))


@app.route('/admin/service-request/<int:request_id>/revoke', methods=['POST'])
@login_required
@admin_required
@limiter.limit("30 per minute")
def admin_revoke_service_request(request_id: int) -> ResponseReturnValue:
    """Revoke a previously approved service request"""
    try:
        service_request = ServiceRequest.query.get_or_404(request_id)
        service_request.status = "Revoked"
        service_request.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        logger.info(f"Admin {current_user.username} revoked service request {request_id}")
        flash(f"Service request #{request_id} revoked successfully", "success")
    except Exception as e:
        logger.error(f"Error revoking service request: {e}")
        flash("An error occurred while revoking the service request", "error")

    return redirect(url_for("admin_service_requests"))


# User Management Routes
@app.route('/admin/users/<int:user_id>/data', methods=['GET'])
@login_required
@admin_required
@limiter.limit("30 per minute")
def get_user_data(user_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, str], int]]:
    """API endpoint to fetch full user data for editing"""
    try:
        user = User.query.get_or_404(user_id)
        
        # Additional authorization check
        if not current_user.is_admin:
            logger.warning(f"Unauthorized access attempt to user data by {current_user.username}")
            return {'error': 'Unauthorized'}, 403
        
        access = user.get_access()

        user_data = {
            'id': user.id,
            'username': user.username,
            'name': user.name,
            'is_admin': user.is_admin,
            'email': user.email,
            'phone': user.phone,
            'laptop': user.laptop,
            'charger': user.charger,
            'keyboard': user.keyboard,
            'mouse': user.mouse,
            'headset': user.headset,
            'access': access
        }

        return user_data
    except Exception as e:
        logger.error(f"Error fetching user data: {e}")
        return {'error': 'Failed to fetch user data'}, 500


@app.route('/admin/users', methods=['GET'])
@login_required
@admin_required
def user_management() -> str:
    """Comprehensive user management interface"""
    all_users: List[User] = User.query.order_by(User.username).all()
    admins: List[User] = [u for u in all_users if u.is_admin]
    employees: List[User] = [u for u in all_users if not u.is_admin]

    logger.info(f"User management accessed by {current_user.username}")
    return render_template('pages/admin/user_management.html',
                           all_users=all_users,
                           admins=admins,
                           employees=employees)


@app.route('/admin/users/create', methods=['POST'])
@login_required
@admin_required
@limiter.limit("10 per hour")
def user_management_create() -> ResponseReturnValue:
    """Create new user with validation"""
    try:
        username = sanitize_input(request.form.get('username', '').strip())
        name = sanitize_input(request.form.get('name', '').strip())
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        email = sanitize_input(request.form.get('email', '').strip())
        phone = sanitize_input(request.form.get('phone', '').strip())
        is_admin = bool(request.form.get('is_admin'))

        if not username or len(username) < 1:
            flash('Username is required', 'error')
            return redirect(url_for('user_management'))

        if not name or len(name) < 1:
            flash('Full name is required', 'error')
            return redirect(url_for('user_management'))

        if not re.match(r'^[a-zA-Z0-9._-]+$', username):
            flash('Username can only contain letters, numbers, dots, underscores, and hyphens', 'error')
            return redirect(url_for('user_management'))

        is_valid, error_msg = validate_password_strength(password)
        if not is_valid:
            flash(error_msg, 'error')
            return redirect(url_for('user_management'))

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('user_management'))

        if User.query.filter_by(username=username).first():
            flash(f'Username "{username}" already exists', 'error')
            return redirect(url_for('user_management'))

        new_user = User(
            username=username,
            name=name,
            is_admin=is_admin,
            email=email if email else None,
            phone=phone if phone else None
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        logger.info(f"Admin {current_user.username} created user {username} (admin={is_admin})")
        flash(f'User "{username}" created successfully as {"Administrator" if is_admin else "Employee"}', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating user: {e}")
        flash('An error occurred while creating the user', 'error')

    return redirect(url_for('user_management'))


@app.route('/admin/users/edit', methods=['POST'])
@login_required
@admin_required
def user_management_edit() -> ResponseReturnValue:
    """Edit existing user details including contact, assets, and access"""
    try:
        user_id = request.form.get('user_id')
        if not user_id:
            flash('User ID is required', 'error')
            return redirect(url_for('user_management'))

        user = User.query.get(int(user_id))
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('user_management'))

        new_username = sanitize_input(request.form.get('username', '').strip())
        new_name = sanitize_input(request.form.get('name', '').strip())
        is_admin = bool(request.form.get('is_admin'))

        if not new_username or len(new_username) < 1:
            flash('Username cannot be empty', 'error')
            return redirect(url_for('user_management'))

        if not new_name or len(new_name) < 1:
            flash('Full name cannot be empty', 'error')
            return redirect(url_for('user_management'))

        if not re.match(r'^[a-zA-Z0-9._-]+$', new_username):
            flash('Username can only contain letters, numbers, dots, underscores, and hyphens', 'error')
            return redirect(url_for('user_management'))

        if new_username != user.username:
            if User.query.filter_by(username=new_username).first():
                flash(f'Username "{new_username}" already exists', 'error')
                return redirect(url_for('user_management'))

        # Validate user details with Pydantic
        try:
            details = UserDetailsUpdate(
                phone=request.form.get('phone'),
                email=request.form.get('email'),
                laptop=request.form.get('laptop'),
                charger=request.form.get('charger'),
                keyboard=request.form.get('keyboard'),
                mouse=request.form.get('mouse'),
                headset=request.form.get('headset'),
                vpn_access=bool(request.form.get('vpn_access')),
                email_access=bool(request.form.get('email_access')),
                biometric_access=bool(request.form.get('biometric_access'))
            )
        except ValidationError as e:
            logger.error(f"Validation error editing user: {e}")
            errors = e.errors()
            for error in errors:
                flash(f"{error['loc'][0]}: {error['msg']}", 'error')
            return redirect(url_for('user_management'))

        old_username = user.username
        user.username = new_username
        user.name = new_name
        user.is_admin = is_admin

        # Update contact info
        user.email = details.email
        user.phone = details.phone

        # Update assets
        user.laptop = details.laptop
        user.charger = details.charger
        user.keyboard = details.keyboard
        user.mouse = details.mouse
        user.headset = details.headset

        # Update access permissions
        access = {
            'vpn': details.vpn_access,
            'email': details.email_access,
            'biometric': details.biometric_access
        }
        user.set_access(access)

        db.session.commit()

        logger.info(f"Admin {current_user.username} updated user {old_username} -> {new_username} (admin={is_admin})")
        flash(f'User "{new_username}" updated successfully', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error editing user: {e}")
        flash('An error occurred while updating the user', 'error')

    return redirect(url_for('user_management'))


@app.route('/admin/users/delete', methods=['POST'])
@login_required
@admin_required
@limiter.limit("5 per hour")
def user_management_delete() -> ResponseReturnValue:
    """Delete user with safety checks"""
    try:
        user_id = request.form.get('user_id')
        if not user_id:
            flash('User ID is required', 'error')
            return redirect(url_for('user_management'))

        user = User.query.get(int(user_id))
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('user_management'))

        if user.id == current_user.id:
            flash('Cannot delete your own account', 'error')
            return redirect(url_for('user_management'))

        username = user.username

        # Delete or orphan all related records
        # Set all user's tickets employee_id to NULL to orphan them
        Ticket.query.filter_by(employee_id=user.id).update({'employee_id': None})
        
        # Set all service requests employee_id to NULL
        ServiceRequest.query.filter_by(employee_id=user.id).update({'employee_id': None})
        
        # Delete onboarding records (CASCADE should handle this, but explicit is better)
        Onboarding.query.filter_by(employee_id=user.id).delete()
        
        # Delete exit records
        EmployeeExit.query.filter_by(employee_id=user.id).delete()
        
        # Delete GitHub access records
        GitHubRepoAccess.query.filter_by(employee_id=user.id).delete()
        
        # Unassign assets
        Asset.query.filter_by(assigned_to=user.id).update({'assigned_to': None, 'status': 'Available'})

        # Finally delete the user
        db.session.delete(user)
        db.session.commit()

        logger.info(f"Admin {current_user.username} deleted user {username}")
        flash(f'User "{username}" deleted successfully', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting user: {e}")
        flash(f'An error occurred while deleting the user: {str(e)}', 'error')

    return redirect(url_for('user_management'))


@app.route('/admin/users/password', methods=['POST'])
@login_required
@admin_required
@limiter.limit("10 per hour")
def user_management_password() -> ResponseReturnValue:
    """Change password for any user"""
    try:
        user_id = request.form.get('user_id')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not user_id:
            flash('Select a user', 'error')
            return redirect(url_for('user_management'))

        user = User.query.get(int(user_id))
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('user_management'))

        is_valid, error_msg = validate_password_strength(new_password)
        if not is_valid:
            flash(error_msg, 'error')
            return redirect(url_for('user_management'))

        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('user_management'))

        user.set_password(new_password)
        db.session.commit()

        logger.info(f"Admin {current_user.username} changed password for user {user.username}")
        flash(f'Password updated successfully for "{user.username}"', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error changing password: {e}")
        flash('An error occurred while changing the password', 'error')

    return redirect(url_for('user_management'))


# GitHub Repository Access Management
@app.route('/admin/github-access', methods=['GET'])
@login_required
@admin_required
def admin_github_access() -> ResponseReturnValue:
    """Admin view for managing GitHub repository access"""
    from sqlalchemy.orm import joinedload
    
    # Get all GitHub access records with employee information (optimized with eager loading)
    access_records = GitHubRepoAccess.query.options(
        joinedload(GitHubRepoAccess.employee)
    ).order_by(GitHubRepoAccess.created_at.desc()).all()
    
    # Get all employees for the grant access form
    employees = User.query.filter_by(is_admin=False).order_by(User.username).all()
    
    return render_template('pages/admin/github_access.html', 
                         access_records=access_records,
                         employees=employees,
                         company_name=COMPANY_NAME)


@app.route('/admin/github-access/grant', methods=['POST'])
@login_required
@admin_required
def admin_grant_github_access() -> ResponseReturnValue:
    """Grant GitHub repository access to an employee"""
    try:
        employee_id = request.form.get('employee_id')
        repo_name = request.form.get('repo_name', '').strip()
        
        if not employee_id or not repo_name:
            flash('Employee and repository name are required', 'error')
            return redirect(url_for('admin_github_access'))
        
        employee = User.query.get(int(employee_id))
        if not employee:
            flash('Employee not found', 'error')
            return redirect(url_for('admin_github_access'))
        
        # Check if access already exists and is active
        existing = GitHubRepoAccess.query.filter_by(
            employee_id=employee.id, 
            repo_name=repo_name, 
            is_active=True
        ).first()
        
        if existing:
            flash(f'Employee already has active access to {repo_name}', 'warning')
            return redirect(url_for('admin_github_access'))
        
        # Create new access record
        access = GitHubRepoAccess(
            employee_id=employee.id,
            repo_name=repo_name,
            is_active=True
        )
        db.session.add(access)
        db.session.commit()
        
        logger.info(f"Admin {current_user.username} granted {employee.username} access to {repo_name}")
        flash(f'Access granted to {employee.username} for repository: {repo_name}', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error granting GitHub access: {e}")
        flash('An error occurred while granting access', 'error')
    
    return redirect(url_for('admin_github_access'))


@app.route('/admin/github-access/revoke/<int:access_id>', methods=['POST'])
@login_required
@admin_required
def admin_revoke_github_access(access_id: int) -> ResponseReturnValue:
    """Revoke GitHub repository access"""
    try:
        access = GitHubRepoAccess.query.get(access_id)
        if not access:
            flash('Access record not found', 'error')
            return redirect(url_for('admin_github_access'))
        
        if not access.is_active:
            flash('Access is already revoked', 'warning')
            return redirect(url_for('admin_github_access'))
        
        access.is_active = False
        access.access_revoked_date = datetime.now(timezone.utc)
        db.session.commit()
        
        logger.info(f"Admin {current_user.username} revoked GitHub access for {access.employee.username} from {access.repo_name}")
        flash(f'Access revoked for {access.employee.username} from repository: {access.repo_name}', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error revoking GitHub access: {e}")
        flash('An error occurred while revoking access', 'error')
    
    return redirect(url_for('admin_github_access'))


# ============================================================================
# ASSETS INVENTORY ROUTES
# ============================================================================

@app.route('/admin/assets', methods=['GET'])
@login_required
@admin_required
def admin_assets() -> str:
    """Admin view for assets inventory management"""
    assets = Asset.query.order_by(Asset.created_at.desc()).all()
    all_users = User.query.order_by(User.username).all()
    admins = [u for u in all_users if u.is_admin]
    employees = [u for u in all_users if not u.is_admin]
    asset_types = CONFIG.get('ASSET_TYPES', [])
    
    # Generate unique 7-digit asset ID
    generated_asset_id = generate_unique_asset_id()
    
    return render_template('pages/admin/assets.html', 
                         assets=assets, 
                         all_users=all_users,
                         admins=admins,
                         employees=employees,
                         asset_types=asset_types,
                         generated_asset_id=generated_asset_id)


@app.route('/admin/assets/create', methods=['POST'])
@login_required
@admin_required
@limiter.limit("20 per hour")
def admin_create_asset() -> ResponseReturnValue:
    """Create new asset with QR code"""
    try:
        asset_data = AssetCreate(
            asset_id=request.form.get('asset_id', ''),
            asset_type=request.form.get('asset_type', ''),
            brand=request.form.get('brand'),
            model=request.form.get('model'),
            serial_number=request.form.get('serial_number'),
            purchase_date=request.form.get('purchase_date'),
            warranty_expiry=request.form.get('warranty_expiry'),
            notes=request.form.get('notes')
        )
        
        # Check if asset ID already exists
        if Asset.query.filter_by(asset_id=asset_data.asset_id).first():
            flash(f'Asset ID {asset_data.asset_id} already exists', 'error')
            return redirect(url_for('admin_assets'))
        
        # Generate QR code with asset information
        qr_data = f"{request.url_root}asset/{asset_data.asset_id}"
        qr_code_img = generate_qr_code(qr_data)
        
        # Check if asset should be assigned to a user
        employee_id = request.form.get('employee_id')
        
        # Create asset
        asset = Asset(
            asset_id=asset_data.asset_id,
            asset_type=asset_data.asset_type,
            brand=asset_data.brand,
            model=asset_data.model,
            serial_number=asset_data.serial_number,
            notes=asset_data.notes,
            qr_code=qr_code_img,
            status='Assigned' if employee_id else 'Available'
        )
        
        # Assign to user if selected
        if employee_id:
            try:
                employee = User.query.get(int(employee_id))
                if employee:
                    asset.assigned_to = employee.id
                    asset.assigned_date = datetime.now(timezone.utc)
                else:
                    logger.warning(f"Employee ID {employee_id} not found during asset assignment")
            except (ValueError, TypeError) as e:
                logger.error(f"Invalid employee ID format: {employee_id}, error: {e}")
        
        # Parse dates with proper error handling
        if asset_data.purchase_date:
            try:
                asset.purchase_date = datetime.strptime(asset_data.purchase_date, '%Y-%m-%d').date()
            except ValueError:
                pass
        
        if asset_data.warranty_expiry:
            try:
                asset.warranty_expiry = datetime.strptime(asset_data.warranty_expiry, '%Y-%m-%d').date()
            except ValueError:
                pass
        
        db.session.add(asset)
        db.session.commit()
        
        logger.info(f"Admin {current_user.username} created asset {asset.asset_id}")
        if employee_id and employee:
            flash(f'Asset {asset.asset_id} created and assigned to {employee.name or employee.username}', 'success')
        else:
            flash(f'Asset {asset.asset_id} created successfully with QR code', 'success')
        
    except ValidationError as e:
        logger.error(f"Validation error creating asset: {e}")
        for error in e.errors():
            flash(f"{error['loc'][0]}: {error['msg']}", 'error')
    except Exception as e:
        logger.error(f"Error creating asset: {e}")
        flash('An error occurred. Please try again or contact support.', 'error')
    
    return redirect(url_for('admin_assets'))


@app.route('/admin/assets/<int:asset_id>/assign', methods=['POST'])
@login_required
@admin_required
def admin_assign_asset(asset_id: int) -> ResponseReturnValue:
    """Assign asset to employee"""
    try:
        asset = Asset.query.get_or_404(asset_id)
        employee_id = request.form.get('employee_id')
        
        if not employee_id:
            flash('Please select an employee', 'error')
            return redirect(url_for('admin_assets'))
        
        employee = User.query.get(int(employee_id))
        if not employee:
            flash('Employee not found', 'error')
            return redirect(url_for('admin_assets'))
        
        asset.assigned_to = employee.id
        asset.assigned_date = datetime.now(timezone.utc)
        asset.status = 'Assigned'
        db.session.commit()
        
        logger.info(f"Admin {current_user.username} assigned asset {asset.asset_id} to {employee.username}")
        flash(f'Asset {asset.asset_id} assigned to {employee.username}', 'success')
        
    except Exception as e:
        logger.error(f"Error assigning asset: {e}")
        flash('An error occurred. Please try again or contact support.', 'error')
    
    return redirect(url_for('admin_assets'))


@app.route('/admin/assets/<int:asset_id>/unassign', methods=['POST'])
@login_required
@admin_required
def admin_unassign_asset(asset_id: int) -> ResponseReturnValue:
    """Unassign asset from employee"""
    try:
        asset = Asset.query.get_or_404(asset_id)
        asset.assigned_to = None
        asset.assigned_date = None
        asset.status = 'Available'
        db.session.commit()
        
        logger.info(f"Admin {current_user.username} unassigned asset {asset.asset_id}")
        flash(f'Asset {asset.asset_id} is now available', 'success')
        
    except Exception as e:
        logger.error(f"Error unassigning asset: {e}")
        flash('An error occurred. Please try again or contact support.', 'error')
    
    return redirect(url_for('admin_assets'))


@app.route('/admin/assets/<int:asset_id>/delete', methods=['POST'])
@login_required
@admin_required
@limiter.limit("10 per hour")
def admin_delete_asset(asset_id: int) -> ResponseReturnValue:
    """Delete asset"""
    try:
        asset = Asset.query.get_or_404(asset_id)
        asset_id_str = asset.asset_id
        db.session.delete(asset)
        db.session.commit()
        
        logger.info(f"Admin {current_user.username} deleted asset {asset_id_str}")
        flash(f'Asset {asset_id_str} deleted successfully', 'success')
        
    except Exception as e:
        logger.error(f"Error deleting asset: {e}")
        flash('An error occurred. Please try again or contact support.', 'error')
    
    return redirect(url_for('admin_assets'))


@app.route('/asset/<asset_id>')
@login_required
def view_asset(asset_id: str) -> str:
    """Protected view for scanned QR code - shows asset and employee details"""
    from sqlalchemy.orm import joinedload
    
    # Use eager loading to fetch asset with employee in one query
    asset = Asset.query.options(joinedload(Asset.employee)).filter_by(asset_id=asset_id).first_or_404()
    
    # Employee is now loaded via relationship
    employee = asset.employee if asset.assigned_to else None
    
    if asset.assigned_to and not employee:
        logger.warning(f"Asset {asset_id} assigned to user {asset.assigned_to} but user not found")
    
    return render_template('pages/asset_view.html', asset=asset, employee=employee, CONFIG=CONFIG)


@app.route('/admin/assets/generate-id', methods=['GET'])
@login_required
@admin_required
def generate_asset_id() -> Dict[str, str]:
    """API endpoint to generate a new unique asset ID"""
    return {'asset_id': generate_unique_asset_id()}


@app.route('/admin/assets/<int:asset_id>/qr')
@login_required
@admin_required
def download_asset_qr(asset_id: int) -> ResponseReturnValue:
    """Download QR code for printing"""
    asset = Asset.query.get_or_404(asset_id)
    
    if not asset.qr_code:
        flash('QR code not found for this asset', 'error')
        return redirect(url_for('admin_assets'))
    
    # Extract base64 data
    qr_data = asset.qr_code.split(',')[1] if ',' in asset.qr_code else asset.qr_code
    qr_bytes = base64.b64decode(qr_data)
    
    return send_file(
        BytesIO(qr_bytes),
        mimetype='image/png',
        as_attachment=True,
        download_name=f'QR_{asset.asset_id}.png'
    )


# ============================================================================
# ONBOARDING ROUTES
# ============================================================================

@app.route('/admin/onboarding', methods=['GET'])
@login_required
@admin_required
def admin_onboarding() -> str:
    """Admin view for employee onboarding"""
    from sqlalchemy.orm import joinedload
    
    # Use eager loading to prevent N+1 query problem
    onboardings = Onboarding.query.options(
        joinedload(Onboarding.employee)
    ).order_by(Onboarding.created_at.desc()).all()
    departments = CONFIG.get('DEPARTMENTS', [])
    return render_template('pages/admin/onboarding.html', 
                         onboardings=onboardings,
                         departments=departments)


@app.route('/admin/onboarding/create', methods=['POST'])
@login_required
@admin_required
def admin_create_onboarding() -> ResponseReturnValue:
    """Create new employee onboarding"""
    try:
        onboarding_data = OnboardingCreate(
            full_name=request.form.get('full_name', ''),
            personal_email=request.form.get('personal_email'),
            phone=request.form.get('phone'),
            emergency_contact_name=request.form.get('emergency_contact_name'),
            emergency_contact_phone=request.form.get('emergency_contact_phone'),
            address=request.form.get('address'),
            date_of_birth=request.form.get('date_of_birth'),
            joining_date=request.form.get('joining_date', ''),
            role=request.form.get('role', ''),
            department=request.form.get('department', ''),
            reporting_manager=request.form.get('reporting_manager'),
            work_location=request.form.get('work_location'),
            employment_type=request.form.get('employment_type')
        )
        
        # Create user account
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        work_email = request.form.get('work_email', '').strip()
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return redirect(url_for('admin_onboarding'))
        
        if User.query.filter_by(username=username).first():
            flash(f'Username {username} already exists', 'error')
            return redirect(url_for('admin_onboarding'))
        
        # Create user
        user = User(
            username=username,
            name=onboarding_data.full_name,
            email=work_email if work_email else None,
            phone=onboarding_data.phone,
            department=onboarding_data.department,
            is_admin=False
        )
        user.set_password(password)
        db.session.add(user)
        db.session.flush()  # Get user ID
        
        # Create onboarding record
        onboarding = Onboarding(
            employee_id=user.id,
            full_name=onboarding_data.full_name,
            personal_email=onboarding_data.personal_email,
            phone=onboarding_data.phone,
            emergency_contact_name=onboarding_data.emergency_contact_name,
            emergency_contact_phone=onboarding_data.emergency_contact_phone,
            address=onboarding_data.address,
            role=onboarding_data.role,
            department=onboarding_data.department,
            reporting_manager=onboarding_data.reporting_manager,
            work_location=onboarding_data.work_location,
            employment_type=onboarding_data.employment_type,
            status='Pending'
        )
        
        # Parse dates
        if onboarding_data.date_of_birth:
            try:
                onboarding.date_of_birth = datetime.strptime(onboarding_data.date_of_birth, '%Y-%m-%d').date()
            except ValueError:
                pass
        
        if onboarding_data.joining_date:
            try:
                onboarding.joining_date = datetime.strptime(onboarding_data.joining_date, '%Y-%m-%d').date()
            except ValueError:
                pass
        
        db.session.add(onboarding)
        db.session.commit()
        
        logger.info(f"Admin {current_user.username} created onboarding for {username}")
        flash(f'Onboarding created for {onboarding_data.full_name}', 'success')
        
    except ValidationError as e:
        logger.error(f"Validation error creating onboarding: {e}")
        for error in e.errors():
            flash(f"{error['loc'][0]}: {error['msg']}", 'error')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating onboarding: {e}")
        flash('An error occurred while creating onboarding', 'error')
    
    return redirect(url_for('admin_onboarding'))


@app.route('/admin/onboarding/<int:onboarding_id>/complete', methods=['POST'])
@login_required
@admin_required
def admin_complete_onboarding(onboarding_id: int) -> ResponseReturnValue:
    """Complete onboarding and send welcome email"""
    try:
        onboarding = Onboarding.query.get_or_404(onboarding_id)
        onboarding.status = 'Completed'
        onboarding.completed_date = datetime.now(timezone.utc)
        
        # Send welcome email
        if not onboarding.welcome_email_sent:
            employee = onboarding.employee
            if send_welcome_email(employee, onboarding):
                onboarding.welcome_email_sent = True
                flash(f'Onboarding completed and welcome email sent to {employee.email}', 'success')
            else:
                flash('Onboarding completed but failed to send welcome email', 'warning')
        
        db.session.commit()
        logger.info(f"Admin {current_user.username} completed onboarding for {onboarding.employee.username}")
        
    except Exception as e:
        logger.error(f"Error completing onboarding: {e}")
        flash('An error occurred while completing onboarding', 'error')
    
    return redirect(url_for('admin_onboarding'))


@app.route('/admin/onboarding/<int:onboarding_id>/resend-email', methods=['POST'])
@login_required
@admin_required
def admin_resend_welcome_email(onboarding_id: int) -> ResponseReturnValue:
    """Resend welcome email"""
    try:
        onboarding = Onboarding.query.get_or_404(onboarding_id)
        employee = onboarding.employee
        
        if send_welcome_email(employee, onboarding):
            onboarding.welcome_email_sent = True
            db.session.commit()
            flash(f'Welcome email resent to {employee.email}', 'success')
        else:
            flash('Failed to send welcome email', 'error')
        
    except Exception as e:
        logger.error(f"Error resending welcome email: {e}")
        flash('An error occurred while sending email', 'error')
    
    return redirect(url_for('admin_onboarding'))


# ============================================================================
# EXIT PROCESS ROUTES
# ============================================================================

@app.route('/admin/exit', methods=['GET'])
@login_required
@admin_required
def admin_exit() -> str:
    """Admin view for employee exit process"""
    from sqlalchemy.orm import joinedload
    
    # Use eager loading to prevent N+1 query problem
    exits = EmployeeExit.query.options(
        joinedload(EmployeeExit.employee)
    ).order_by(EmployeeExit.created_at.desc()).all()
    employees = User.query.filter_by(is_admin=False).order_by(User.username).all()
    return render_template('pages/admin/exit.html', exits=exits, employees=employees)


@app.route('/admin/exit/create', methods=['POST'])
@login_required
@admin_required
def admin_create_exit() -> ResponseReturnValue:
    """Initiate employee exit process"""
    try:
        employee_id = request.form.get('employee_id')
        if not employee_id:
            flash('Please select an employee', 'error')
            return redirect(url_for('admin_exit'))
        
        employee = User.query.get(int(employee_id))
        if not employee:
            flash('Employee not found', 'error')
            return redirect(url_for('admin_exit'))
        
        # Check if exit already exists
        if EmployeeExit.query.filter_by(employee_id=employee.id, status='Initiated').first():
            flash(f'Exit process already initiated for {employee.username}', 'warning')
            return redirect(url_for('admin_exit'))
        
        exit_data = ExitCreate(
            exit_date=request.form.get('exit_date', ''),
            last_working_day=request.form.get('last_working_day', ''),
            reason=request.form.get('reason'),
            exit_type=request.form.get('exit_type'),
            notes=request.form.get('notes')
        )
        
        employee_exit = EmployeeExit(
            employee_id=employee.id,
            reason=exit_data.reason,
            exit_type=exit_data.exit_type,
            notes=exit_data.notes,
            status='Initiated'
        )
        
        # Parse dates
        if exit_data.exit_date:
            try:
                employee_exit.exit_date = datetime.strptime(exit_data.exit_date, '%Y-%m-%d').date()
            except ValueError:
                pass
        
        if exit_data.last_working_day:
            try:
                employee_exit.last_working_day = datetime.strptime(exit_data.last_working_day, '%Y-%m-%d').date()
            except ValueError:
                pass
        
        db.session.add(employee_exit)
        db.session.commit()
        
        logger.info(f"Admin {current_user.username} initiated exit for {employee.username}")
        flash(f'Exit process initiated for {employee.username}', 'success')
        
    except ValidationError as e:
        logger.error(f"Validation error creating exit: {e}")
        for error in e.errors():
            flash(f"{error['loc'][0]}: {error['msg']}", 'error')
    except Exception as e:
        logger.error(f"Error creating exit: {e}")
        flash('An error occurred while initiating exit process', 'error')
    
    return redirect(url_for('admin_exit'))


@app.route('/admin/exit/<int:exit_id>/update', methods=['POST'])
@login_required
@admin_required
def admin_update_exit(exit_id: int) -> ResponseReturnValue:
    """Update exit process checklist"""
    try:
        employee_exit = EmployeeExit.query.get_or_404(exit_id)
        
        # Update checklist items
        employee_exit.assets_returned = bool(request.form.get('assets_returned'))
        employee_exit.email_access_revoked = bool(request.form.get('email_access_revoked'))
        employee_exit.vpn_access_revoked = bool(request.form.get('vpn_access_revoked'))
        employee_exit.system_access_revoked = bool(request.form.get('system_access_revoked'))
        employee_exit.building_access_revoked = bool(request.form.get('building_access_revoked'))
        employee_exit.exit_interview_completed = bool(request.form.get('exit_interview_completed'))
        employee_exit.clearance_certificate_issued = bool(request.form.get('clearance_certificate_issued'))
        
        # Update notes
        if request.form.get('assets_notes'):
            employee_exit.assets_notes = request.form.get('assets_notes')
        
        # Check if all items completed
        if (employee_exit.assets_returned and 
            employee_exit.email_access_revoked and 
            employee_exit.vpn_access_revoked and 
            employee_exit.system_access_revoked and 
            employee_exit.building_access_revoked and 
            employee_exit.exit_interview_completed and 
            employee_exit.clearance_certificate_issued):
            employee_exit.status = 'Completed'
            employee_exit.completed_date = datetime.now(timezone.utc)
        else:
            employee_exit.status = 'In Progress'
        
        db.session.commit()
        
        logger.info(f"Admin {current_user.username} updated exit for {employee_exit.employee.username}")
        flash('Exit process updated', 'success')
        
    except Exception as e:
        logger.error(f"Error updating exit: {e}")
        flash('An error occurred while updating exit process', 'error')
    
    return redirect(url_for('admin_exit'))


@app.route('/admin/exit/<int:exit_id>/complete', methods=['POST'])
@login_required
@admin_required
def admin_complete_exit(exit_id: int) -> ResponseReturnValue:
    """Mark exit process as completed"""
    try:
        employee_exit = EmployeeExit.query.get_or_404(exit_id)
        employee_exit.status = 'Completed'
        employee_exit.completed_date = datetime.now(timezone.utc)
        db.session.commit()
        
        logger.info(f"Admin {current_user.username} completed exit for {employee_exit.employee.username}")
        flash(f'Exit process completed for {employee_exit.employee.username}', 'success')
        
    except Exception as e:
        logger.error(f"Error completing exit: {e}")
        flash('An error occurred while completing exit process', 'error')
    
    return redirect(url_for('admin_exit'))


# Initialize database and seed default data
def bootstrap() -> None:
    db.create_all()

    users_cfg = CONFIG.get('USERS', [])
    created = 0
    for u in users_cfg:
        username = u.get('name')
        if not username:
            continue
        if User.query.filter_by(username=username).first():
            continue
        is_admin = bool(u.get('Admin', False))
        
        # Validate admin password strength
        pw = u.get('password', '')
        if is_admin and pw:
            is_valid, error_msg = validate_password_strength(pw)
            if not is_valid:
                logger.error(f"Admin password validation failed: {error_msg}")
                raise RuntimeError(f"Admin password does not meet security requirements: {error_msg}")
        
        user = User(username=username, is_admin=is_admin)
        user.name = u.get('full_name') or username
        user.department = u.get('department')
        user.email = u.get('email') or None
        user.phone = u.get('phone') or None
        assets = u.get('assets', {})
        user.laptop = assets.get('laptop') or None
        user.charger = assets.get('charger') or None
        user.keyboard = assets.get('keyboard') or None
        user.mouse = assets.get('mouse') or None
        user.headset = assets.get('headset') or None
        if pw:
            user.set_password(pw)
        else:
            if is_admin:
                raise RuntimeError(f"Admin user '{username}' requires a password. Set ADMIN_PASSWORD environment variable.")
        db.session.add(user)
        created += 1

    if created:
        print(f"Added {created} user(s) from config")

    db.session.commit()


if __name__ == "__main__":
    with app.app_context():
        bootstrap()
    
    # Only start scheduler if not in debug mode or if explicitly enabled
    DEBUG_MODE = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    if not DEBUG_MODE or os.environ.get('ENABLE_SCHEDULER', 'False').lower() == 'true':
        # Initialize background scheduler for automated emails
        scheduler = BackgroundScheduler()
        
        # Check birthdays daily at 9:00 AM
        scheduler.add_job(
            func=check_birthdays,
            trigger=CronTrigger(hour=9, minute=0),
            id='birthday_check',
            name='Check employee birthdays',
            replace_existing=True
        )
        
        # Check work anniversaries daily at 9:00 AM
        scheduler.add_job(
            func=check_anniversaries,
            trigger=CronTrigger(hour=9, minute=0),
            id='anniversary_check',
            name='Check work anniversaries',
            replace_existing=True
        )
        
        scheduler.start()
        logger.info("Background scheduler started for automated emails")
    else:
        scheduler = None
        logger.info("Background scheduler disabled in debug mode")
    
    try:
        # Get port from environment or use default
        port = int(os.environ.get('PORT', '5004'))
        debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
        app.run(host="0.0.0.0", port=port, debug=debug_mode)
    except (KeyboardInterrupt, SystemExit):
        if scheduler:
            scheduler.shutdown()
            logger.info("Background scheduler shut down")
