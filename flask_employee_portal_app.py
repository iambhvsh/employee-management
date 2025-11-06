"""Flask Employee Portal - Role-based access system"""

# Core imports for Flask web framework, authentication, validation, and security
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask.wrappers import Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
  LoginManager, UserMixin, login_user, logout_user, login_required, current_user
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from typing import Dict, Optional, Union, List, Any, Tuple, Callable, TypeVar, cast, TYPE_CHECKING
from typing_extensions import ParamSpec
from pydantic import BaseModel, Field, EmailStr, field_validator, ValidationError
import os
import json
import re
import logging
from functools import wraps

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
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super_secret_key_change_in_production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Company configuration
COMPANY_NAME = os.environ.get('COMPANY_NAME', 'Employee Portal')
app.config['COMPANY_NAME'] = COMPANY_NAME
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600
app.config['WTF_CSRF_TIME_LIMIT'] = None

# Development-only: disable for local testing without HTTPS
app.config['SESSION_COOKIE_SECURE'] = False
app.config['REMEMBER_COOKIE_SECURE'] = False

# Initialize database, CSRF protection, and login manager
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"


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
    response.headers['Content-Security-Policy'] = "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com"
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
    password: str = Field(..., min_length=6)

    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username format"""
        v = v.strip()
        if not re.match(r'^[a-zA-Z0-9._-]+$', v):
            raise ValueError('Username can only contain letters, numbers, dots, underscores, and hyphens')
        return v


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
    """Validate ticket status is one of the allowed values"""
    return status in ['Pending', 'Approved', 'Rejected']


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


# Predefined ticket categories for structured issue tracking
TICKET_GROUPS = {
    "ITEMS": ["KEYBOARD", "MOUSE", "LAPTOP ISSUE", "CHARGER", "HEADSET", "RAM CHANGE", "SCREEN ISSUE", "KEYPAD ISSUE", "TOUCHPAD ISSUE"],
    "ACCESS": ["VPN ACCESS", "EMAIL ACCESS", "BIOMETRIC ACCESS"],
    "ISSUES": ["SOFTWARE ISSUE", "NETWORK ISSUE", "PERFORMANCE ISSUE"],
    "OTHER": ["OTHER"]
}

# Service request categories and types
SERVICE_REQUEST_TYPES = {
    "DevOps": ["Add Port", "Add VPN", "Add Route", "Add Firewall"],
    "Developer": ["GitHub Access Request"]
}


# Database models
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    __allow_unmapped__ = True

    id: Any = db.Column(db.Integer, primary_key=True)
    username: Any = db.Column(db.String(80), unique=True, nullable=False)
    password_hash: Any = db.Column(db.String(200), nullable=False)
    is_admin: Any = db.Column(db.Boolean, default=False)
    
    # Department field for organizing employees
    department: Any = db.Column(db.String(100))

    phone: Any = db.Column(db.String(50))
    email: Any = db.Column(db.String(120))
    laptop: Any = db.Column(db.String(200))
    charger: Any = db.Column(db.String(200))
    keyboard: Any = db.Column(db.String(200))
    mouse: Any = db.Column(db.String(200))
    headset: Any = db.Column(db.String(200))
    
    # Additional asset fields for mobile devices and bags
    more_device: Any = db.Column(db.String(200))  # Mobile devices for mobile developers
    bags: Any = db.Column(db.String(200))  # Office-allotted bags

    # Access permissions stored as JSON
    access_json: Any = db.Column(db.Text, default='{}')

    # Flag indicating if employee has filled their details
    details_filled: Any = db.Column(db.Boolean, default=False)

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


# Flask-Login user loader callback
@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    return db.session.get(User, int(user_id))


# Application routes
@app.route("/")
def index():
    """Redirect authenticated users to their respective dashboard"""
    if current_user.is_authenticated:
        return redirect(url_for("admin_dashboard" if current_user.is_admin else "employee_dashboard_redirect"))
    return redirect(url_for("login"))


# Authentication routes
@app.route("/login", methods=["GET", "POST"])
def login() -> Union[Response, str]:
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
                         employee_departments=employee_departments,
                         company_name=COMPANY_NAME)


@app.route("/logout")
@login_required
def logout() -> Response:
    logout_user()
    flash("You’ve been logged out successfully.", "success")
    return redirect(url_for("login"))


@app.route('/employee/dashboard')
@login_required
def employee_dashboard_redirect() -> Response:
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('employee_details'))


# Employee area routes
@app.route('/employee/details', methods=['GET', 'POST'])
@login_required
def employee_details() -> Union[Response, str]:
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
def employee_raise() -> Union[Response, str]:
    if current_user.is_admin:
        flash('Admins cannot raise employee tickets here', 'error')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        try:
            # Validate ticket data with Pydantic
            ticket_data = TicketCreate(
                item=request.form.get('item', ''),
                reason=request.form.get('reason', '')
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
            flash('An error occurred while creating the ticket', 'error')
            return redirect(url_for('employee_raise'))

    tickets: List[Ticket] = Ticket.query.filter_by(employee_id=current_user.id).order_by(Ticket.created_at.desc()).all()
    return render_template('pages/employee/raise_ticket.html', groups=TICKET_GROUPS, tickets=tickets)


@app.route('/employee/service-requests', methods=['GET', 'POST'])
@login_required
def employee_service_requests() -> Union[Response, str]:
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
                details=request.form.get('details', '')
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
            flash('An error occurred while creating the service request', 'error')
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
    total_employees = User.query.filter_by(is_admin=False).count()
    total_tickets = Ticket.query.count()
    pending_tickets = Ticket.query.filter_by(status='Pending').count()
    approved_tickets = Ticket.query.filter_by(status='Approved').count()
    rejected_tickets = Ticket.query.filter_by(status='Rejected').count()

    stats = {
        'total_employees': total_employees,
        'total_tickets': total_tickets,
        'pending_tickets': pending_tickets,
        'approved_tickets': approved_tickets,
        'rejected_tickets': rejected_tickets
    }

    logger.info(f"Admin dashboard accessed by {current_user.username}")
    return render_template('pages/admin/dashboard.html', stats=stats)


@app.route('/admin/employees', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_employee_details() -> Union[Response, str]:
    if request.method == 'POST':
        uid = request.form.get('user_id')
        if not uid:
            flash('Select an employee before saving', 'error')
            return redirect(url_for('admin_employee_details'))

        user = User.query.get(int(uid))
        if not user:
            flash('Employee not found', 'error')
            return redirect(url_for('admin_employee_details'))

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
                vpn_access=bool(request.form.get('vpn_access')),
                email_access=bool(request.form.get('email_access')),
                biometric_access=bool(request.form.get('biometric_access'))
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
            logger.info(f"Admin {current_user.username} updated employee {user.username}")
            flash('Employee updated', 'success')
            return redirect(url_for('admin_employee_details'))

        except ValidationError as e:
            logger.error(f"Validation error updating employee: {e}")
            errors = e.errors()
            for error in errors:
                flash(f"{error['loc'][0]}: {error['msg']}", 'error')
            return redirect(url_for('admin_employee_details'))
        except Exception as e:
            logger.error(f"Error updating employee: {e}")
            flash('An error occurred', 'error')
            return redirect(url_for('admin_employee_details'))

    employees: List[User] = User.query.filter_by(is_admin=False).order_by(User.username).all()
    return render_template('pages/admin/employees.html', employees=employees)


@app.route('/admin/employees/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_employees() -> Union[Response, str]:
    if request.method == 'POST':
        uid = request.form.get('user_id')
        if not uid:
            flash('Select an employee before saving', 'error')
            return redirect(url_for('admin_employees'))

        user = User.query.get(int(uid))
        if not user:
            flash('Employee not found', 'error')
            return redirect(url_for('admin_employees'))

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
                vpn_access=bool(request.form.get('vpn_access')),
                email_access=bool(request.form.get('email_access')),
                biometric_access=bool(request.form.get('biometric_access'))
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
            return redirect(url_for('admin_employees'))

        except ValidationError as e:
            logger.error(f"Validation error updating employee: {e}")
            errors = e.errors()
            for error in errors:
                flash(f"{error['loc'][0]}: {error['msg']}", 'error')
            return redirect(url_for('admin_employees'))
        except Exception as e:
            logger.error(f"Error updating employee: {e}")
            flash('An error occurred', 'error')
            return redirect(url_for('admin_employees'))

    employees: List[User] = User.query.filter_by(is_admin=False).order_by(User.username).all()
    
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
    
    return render_template('pages/admin/employees_manage.html', employees=employees, employees_data=employees_data)


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
def admin_raise() -> Union[Response, str]:
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
def admin_approve(ticket_id: int) -> Response:
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        if not validate_ticket_status(ticket.status):
            flash("Invalid ticket status", "error")
            return redirect(url_for("admin_tickets"))

        ticket.status = "Approved"
        ticket.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        logger.info(f"Admin {current_user.username} approved ticket {ticket_id}")
        flash(f"Ticket {ticket_id} approved successfully", "success")
    except Exception as e:
        logger.error(f"Error approving ticket: {e}")
        flash("An error occurred while approving the ticket", "error")

    return redirect(url_for("admin_tickets"))


@app.route('/admin/ticket/<int:ticket_id>/reject', methods=['POST'])
@login_required
@admin_required
def admin_reject(ticket_id: int) -> Response:
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        if not validate_ticket_status(ticket.status):
            flash("Invalid ticket status", "error")
            return redirect(url_for("admin_tickets"))

        ticket.status = "Rejected"
        ticket.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        logger.info(f"Admin {current_user.username} rejected ticket {ticket_id}")
        flash(f"Ticket {ticket_id} rejected successfully", "success")
    except Exception as e:
        logger.error(f"Error rejecting ticket: {e}")
        flash("An error occurred while rejecting the ticket", "error")

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
def admin_approve_service_request(request_id: int) -> Response:
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
def admin_reject_service_request(request_id: int) -> Response:
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
def admin_revoke_service_request(request_id: int) -> Response:
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
def get_user_data(user_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, str], int]]:
    """API endpoint to fetch full user data for editing"""
    try:
        user = User.query.get_or_404(user_id)
        access = user.get_access()

        user_data = {
            'id': user.id,
            'username': user.username,
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
def user_management_create() -> Response:
    """Create new user with validation"""
    try:
        username = sanitize_input(request.form.get('username', '').strip())
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        email = sanitize_input(request.form.get('email', '').strip())
        phone = sanitize_input(request.form.get('phone', '').strip())
        is_admin = bool(request.form.get('is_admin'))

        if not username or len(username) < 1:
            flash('Username is required', 'error')
            return redirect(url_for('user_management'))

        if not re.match(r'^[a-zA-Z0-9._-]+$', username):
            flash('Username can only contain letters, numbers, dots, underscores, and hyphens', 'error')
            return redirect(url_for('user_management'))

        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return redirect(url_for('user_management'))

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('user_management'))

        if User.query.filter_by(username=username).first():
            flash(f'Username "{username}" already exists', 'error')
            return redirect(url_for('user_management'))

        new_user = User(
            username=username,
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
def user_management_edit() -> Response:
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
        is_admin = bool(request.form.get('is_admin'))

        if not new_username or len(new_username) < 1:
            flash('Username cannot be empty', 'error')
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
def user_management_delete() -> Response:
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

        # Set all user's tickets employee_id to NULL to orphan them
        Ticket.query.filter_by(employee_id=user.id).update({'employee_id': None})

        db.session.delete(user)
        db.session.commit()

        logger.info(f"Admin {current_user.username} deleted user {username}")
        flash(f'User "{username}" deleted successfully', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting user: {e}")
        flash('An error occurred while deleting the user', 'error')

    return redirect(url_for('user_management'))


@app.route('/admin/users/password', methods=['POST'])
@login_required
@admin_required
def user_management_password() -> Response:
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

        if len(new_password) < 6:
            flash('Password must be at least 6 characters', 'error')
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
def admin_github_access() -> Union[Response, str]:
    """Admin view for managing GitHub repository access"""
    # Get all GitHub access records with employee information
    access_records = db.session.query(GitHubRepoAccess, User).join(User).order_by(GitHubRepoAccess.created_at.desc()).all()
    
    # Get all employees for the grant access form
    employees = User.query.filter_by(is_admin=False).order_by(User.username).all()
    
    return render_template('pages/admin/github_access.html', 
                         access_records=access_records,
                         employees=employees,
                         company_name=COMPANY_NAME)


@app.route('/admin/github-access/grant', methods=['POST'])
@login_required
@admin_required
def admin_grant_github_access() -> Response:
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
def admin_revoke_github_access(access_id: int) -> Response:
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


# Initialize database and seed default data
def bootstrap() -> None:
    db.create_all()

    if not User.query.filter_by(username="Tajuddin.S").first():
        admin = User(username="Tajuddin.S", is_admin=True)
        admin.set_password("Admin@123")
        db.session.add(admin)
        print("Created default admin user")

    # Employees with departments
    employees = [
        ("MohanTeja", "Engineering"),
        ("Hari", "Engineering"),
        ("Aparna", "HR"),
        ("Ramu", "Operations"),
        ("Sai Prasanth", "Engineering")
    ]
    employees_created = 0
    for username, department in employees:
        if not User.query.filter_by(username=username).first():
            emp = User(username=username, is_admin=False)
            emp.department = department
            emp.set_password("Ckompare")
            db.session.add(emp)
            employees_created += 1

    if employees_created > 0:
        print(f"Added {employees_created} employee(s)")

    db.session.commit()


if __name__ == "__main__":
    with app.app_context():
        bootstrap()
    app.run(host="0.0.0.0", port=5004, debug=True)
