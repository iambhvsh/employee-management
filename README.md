# Flask Employee Portal

A comprehensive role-based employee management system built with Flask, featuring ticket management, asset tracking, onboarding/offboarding workflows, and automated email notifications.

## Features

### For Employees
- **Personal Dashboard** - View and manage personal information
- **Ticket System** - Raise tickets for equipment, access requests, and issues
- **Service Requests** - Submit DevOps and Developer service requests (GitHub access, VPN, ports, etc.)
- **Asset Tracking** - View assigned company assets

### For Administrators
- **User Management** - Create, edit, delete users and manage passwords
- **Ticket Management** - Review and approve/reject employee tickets
- **Service Request Management** - Handle DevOps and Developer service requests
- **Asset Inventory** - Track company assets with QR codes
- **GitHub Access Management** - Grant and revoke repository access
- **Onboarding** - Streamlined employee onboarding with automated welcome emails
- **Exit Process** - Manage employee offboarding with checklist tracking
- **Dashboard** - System statistics and overview

### Security Features
- CSRF protection on all forms
- Rate limiting on sensitive endpoints
- Password strength validation
- Secure session management
- Input sanitization and validation using Pydantic
- Security headers (CSP, HSTS, X-Frame-Options, etc.)

### Automation
- Automated birthday emails
- Work anniversary notifications
- Welcome emails for new employees
- Background scheduler for periodic tasks

## Technology Stack

- **Backend**: Flask 3.0.0
- **Database**: SQLite (SQLAlchemy ORM)
- **Authentication**: Flask-Login
- **Security**: Flask-WTF (CSRF), Flask-Limiter (Rate limiting)
- **Validation**: Pydantic
- **Email**: Flask-Mail (SMTP)
- **Scheduling**: APScheduler
- **QR Codes**: qrcode, Pillow

---

## Installation & Setup

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Virtual environment tool (venv, virtualenv, or conda)

### Platform-Specific Setup

#### Linux / macOS

```bash
# Clone or download the repository
cd flask_employee_portal_app

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env

# Edit .env file with your configuration
nano .env  # or use your preferred editor
```

#### Windows

```cmd
# Clone or download the repository
cd flask_employee_portal_app

# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
copy .env.example .env

# Edit .env file with your configuration
notepad .env
```

### Environment Configuration

Edit the `.env` file with your settings:

```env
# REQUIRED: Generate a secure secret key
SECRET_KEY=your-secret-key-here

# REQUIRED: Set admin password (must meet complexity requirements)
ADMIN_PASSWORD=YourSecurePassword123!

# Flask Configuration
FLASK_ENV=development
FLASK_DEBUG=False

# Company Configuration
COMPANY_NAME=Your Company Name

# Server Configuration
PORT=5004

# Email Configuration (Optional - leave MAIL_USERNAME empty to disable)
MAIL_SERVER=smtp.office365.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@company.com
MAIL_PASSWORD=your-email-password
MAIL_DEFAULT_SENDER=your-email@company.com

# Scheduler Configuration (requires email to be configured)
ENABLE_SCHEDULER=False

# Security Configuration (set to True in production with HTTPS)
SESSION_COOKIE_SECURE=False
REMEMBER_COOKIE_SECURE=False
```

#### Generate Secret Key

**Linux/macOS:**
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

**Windows:**
```cmd
python -c "import secrets; print(secrets.token_hex(32))"
```

#### Password Requirements

Admin password must contain:
- At least 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (!@#$%^&*(),.?":{}|<>)

### Database Initialization

The database will be automatically created on first run. The application will:
1. Create all necessary tables
2. Create the admin user from config
3. Initialize the database schema

### Running the Application

#### Development Mode

**Linux/macOS:**
```bash
# Activate virtual environment
source venv/bin/activate

# Run the application
python flask_employee_portal_app.py
```

**Windows:**
```cmd
# Activate virtual environment
venv\Scripts\activate

# Run the application
python flask_employee_portal_app.py
```

The application will be available at: `http://localhost:5004`

#### Production Mode

For production, set these environment variables:
```env
FLASK_ENV=production
FLASK_DEBUG=False
SESSION_COOKIE_SECURE=True
REMEMBER_COOKIE_SECURE=True
ENABLE_SCHEDULER=True
```

---

## Deployment

### Bare Metal Server Deployment

#### Option 1: Using Gunicorn (Recommended for Production)

**Install Gunicorn:**
```bash
pip install gunicorn
```

**Run with Gunicorn:**
```bash
# Basic usage
gunicorn -w 4 -b 0.0.0.0:5004 flask_employee_portal_app:app

# With more workers and timeout
gunicorn -w 4 -b 0.0.0.0:5004 --timeout 120 --access-logfile - --error-logfile - flask_employee_portal_app:app
```

**Create systemd service (Linux):**

Create `/etc/systemd/system/employee-portal.service`:
```ini
[Unit]
Description=Flask Employee Portal
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/path/to/flask_employee_portal_app
Environment="PATH=/path/to/flask_employee_portal_app/venv/bin"
ExecStart=/path/to/flask_employee_portal_app/venv/bin/gunicorn -w 4 -b 0.0.0.0:5004 flask_employee_portal_app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

**Enable and start service:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable employee-portal
sudo systemctl start employee-portal
sudo systemctl status employee-portal
```

#### Option 2: Using Nginx as Reverse Proxy

**Install Nginx:**

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install nginx
```

**CentOS/RHEL:**
```bash
sudo yum install nginx
```

**Configure Nginx:**

Create `/etc/nginx/sites-available/employee-portal`:
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5004;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Increase timeout for long-running requests
    proxy_connect_timeout 300;
    proxy_send_timeout 300;
    proxy_read_timeout 300;
    send_timeout 300;
}
```

**Enable site:**
```bash
sudo ln -s /etc/nginx/sites-available/employee-portal /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

#### Option 3: Using Apache as Reverse Proxy

**Install Apache and mod_proxy:**

**Ubuntu/Debian:**
```bash
sudo apt install apache2
sudo a2enmod proxy proxy_http
```

**Configure Apache:**

Create `/etc/apache2/sites-available/employee-portal.conf`:
```apache
<VirtualHost *:80>
    ServerName your-domain.com

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:5004/
    ProxyPassReverse / http://127.0.0.1:5004/

    ErrorLog ${APACHE_LOG_DIR}/employee-portal-error.log
    CustomLog ${APACHE_LOG_DIR}/employee-portal-access.log combined
</VirtualHost>
```

**Enable site:**
```bash
sudo a2ensite employee-portal
sudo systemctl restart apache2
```

### SSL/HTTPS Setup with Let's Encrypt

**Install Certbot:**

**Ubuntu/Debian:**
```bash
sudo apt install certbot python3-certbot-nginx
```

**Obtain certificate (Nginx):**
```bash
sudo certbot --nginx -d your-domain.com
```

**Obtain certificate (Apache):**
```bash
sudo apt install python3-certbot-apache
sudo certbot --apache -d your-domain.com
```

**Auto-renewal:**
```bash
sudo certbot renew --dry-run
```

### Docker Deployment (Optional)

**Create Dockerfile:**
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5004

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5004", "flask_employee_portal_app:app"]
```

**Create docker-compose.yml:**
```yaml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "5004:5004"
    env_file:
      - .env
    volumes:
      - ./instance:/app/instance
    restart: unless-stopped
```

**Run with Docker:**
```bash
docker-compose up -d
```

---

## Configuration

### Email Setup

The application supports automated emails for:
- Welcome emails for new employees
- Birthday wishes
- Work anniversary notifications

**Supported Email Providers:**

**Office 365/Outlook:**
```env
MAIL_SERVER=smtp.office365.com
MAIL_PORT=587
MAIL_USE_TLS=True
```

**Gmail:**
```env
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
```
*Note: For Gmail, you need to use an App Password, not your regular password.*

**Custom SMTP:**
```env
MAIL_SERVER=your-smtp-server.com
MAIL_PORT=587
MAIL_USE_TLS=True
```

### Scheduler Configuration

The background scheduler runs automated tasks:
- Birthday checks (daily at 9:00 AM)
- Anniversary checks (daily at 9:00 AM)

To enable:
```env
ENABLE_SCHEDULER=True
```

*Note: Email configuration must be set up for scheduler to work.*

### Customization

Edit `config.py` to customize:
- Company name
- Departments
- Asset types
- Ticket categories
- Service request types

---

## Usage

### First Login

1. Navigate to `http://localhost:5004`
2. Login with admin credentials from `.env` file
3. Default username is set in `config.py` (check `USERS` section)

### Admin Tasks

**Create New Employee:**
1. Go to "User Management"
2. Click "Create New User"
3. Fill in details and set password
4. Assign role (Admin or Employee)

**Manage Tickets:**
1. Go to "Tickets"
2. View all employee tickets
3. Approve or reject tickets

**Asset Management:**
1. Go to "Assets Inventory"
2. Add new assets with QR codes
3. Assign assets to employees
4. Download QR codes for printing

**Onboarding:**
1. Go to "Onboarding"
2. Create new employee onboarding
3. Complete checklist items
4. Send welcome email

### Employee Tasks

**Update Profile:**
1. Go to "My Details"
2. Fill in personal information
3. Submit (one-time edit only)

**Raise Ticket:**
1. Go to "Raise Ticket"
2. Select item/issue type
3. Provide detailed reason
4. Submit for approval

**Service Requests:**
1. Go to "Service Requests"
2. Select category (DevOps/Developer)
3. Choose request type
4. Submit request

---

## Security Best Practices

### Production Deployment

1. **Use HTTPS**: Always use SSL/TLS in production
2. **Strong Passwords**: Enforce password complexity
3. **Environment Variables**: Never commit `.env` file
4. **Database**: Use PostgreSQL or MySQL instead of SQLite
5. **Firewall**: Restrict access to necessary ports only
6. **Updates**: Keep dependencies updated
7. **Backups**: Regular database backups
8. **Monitoring**: Set up application monitoring

### Firewall Configuration

**Ubuntu/Debian (UFW):**
```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

**CentOS/RHEL (firewalld):**
```bash
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

---

## Database Backup

### SQLite Backup

```bash
# Create backup
cp instance/app.db instance/app.db.backup

# Scheduled backup (cron)
0 2 * * * cp /path/to/instance/app.db /path/to/backups/app.db.$(date +\%Y\%m\%d)
```

### Migration to PostgreSQL (Recommended for Production)

1. Install PostgreSQL
2. Install psycopg2: `pip install psycopg2-binary`
3. Update `.env`:
```env
DATABASE_URL=postgresql://username:password@localhost/employee_portal
```
4. Update `flask_employee_portal_app.py`:
```python
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///app.db')
```

---

## Maintenance

### Update Dependencies

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate  # Windows

# Update packages
pip install --upgrade -r requirements.txt
```

### Clear Sessions

```bash
# Remove old session files if using filesystem sessions
rm -rf flask_session/*
```

---

### Development Setup

```bash
# Install development dependencies
pip install -r requirements.txt

# Enable debug mode
export FLASK_DEBUG=True  # Linux/macOS
set FLASK_DEBUG=True  # Windows

# Run with auto-reload
python flask_employee_portal_app.py
```