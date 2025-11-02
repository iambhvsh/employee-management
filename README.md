# Employee Portal - Flask Application

A role-based employee management system built with Flask that provides separate dashboards for administrators and employees with ticket management capabilities.

## Features

- **Role-Based Access Control**: Separate admin and employee dashboards with different permissions
- **User Authentication**: Secure login system with password hashing
- **Employee Management**: Admin can create, view, and manage employee accounts
- **Ticket System**: Employees can raise tickets, admins can approve/reject them
- **Dark/Light Mode**: Theme switching with persistent user preference
- **CSRF Protection**: Built-in security against cross-site request forgery
- **Responsive UI**: Clean and modern interface that works on all devices

## Quick Start for Server Deployment

**To deploy on your company server with IP:PORT access:**

1. Edit `flask_employee_portal_app.py` line 984:
   ```python
   app.run(host="0.0.0.0", port=YOUR_PORT, debug=False)
   ```

2. Run the application:
   ```bash
   python flask_employee_portal_app.py
   ```

3. Access via browser:
   ```
   http://YOUR_SERVER_IP:YOUR_PORT
   ```

**Example**: If your server IP is `192.168.1.100` and you set port to `8080`, access via `http://192.168.1.100:8080`

See [Server Deployment](#server-deployment-company-bare-metal--production-server) section for detailed instructions.

## Tech Stack

- **Backend**: Flask 3.0.0
- **Database**: SQLite with SQLAlchemy ORM
- **Authentication**: Flask-Login
- **Validation**: Pydantic with email validation
- **Security**: Flask-WTF CSRF protection, Werkzeug password hashing

## Project Structure

```
employee_portal/
├── flask_employee_portal_app.py  # Main application file
├── requirements.txt               # Python dependencies
├── seed_tickets.py               # Script to seed sample tickets
├── static/                       # Static assets
│   ├── script.js                # JavaScript functionality
│   └── styles.css               # Application styles
├── templates/                    # HTML templates
│   ├── _base.html               # Base template
│   ├── login.html               # Login page
│   ├── layouts/                 # Layout templates
│   └── pages/                   # Page templates
│       ├── admin/               # Admin pages
│       └── employee/            # Employee pages
└── instance/                     # Instance folder (contains database)
```

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

## Installation & Setup

### 1. Clone the Repository

```bash
git clone <your-repository-url>
cd employee_portal
```

### 2. Create a Virtual Environment

⚠️ **Important**: You must create a virtual environment before installing dependencies. The `venv` folder is not included in the repository.

**Windows (PowerShell):**
```powershell
# Create virtual environment
python -m venv venv

# Activate it
.\venv\Scripts\Activate.ps1
```

**If you get an execution policy error on PowerShell, run:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Windows (Command Prompt):**
```cmd
# Create virtual environment
python -m venv venv

# Activate it
venv\Scripts\activate.bat
```

**Linux/Mac:**
```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate
```

**Verify activation**: Your terminal should show `(venv)` at the beginning of the prompt.

### 3. Install Dependencies

Make sure your virtual environment is activated (you should see `(venv)` in your terminal), then install the required packages:

```bash
pip install -r requirements.txt
```

### 4. Initialize the Database

The application will automatically create the database on first run. The database file will be created at `instance/app.db`.

### 5. Create Admin User

When you first run the application, you'll need to create an admin user. You can do this through the application or by running Python commands:

```python
from flask_employee_portal_app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    admin = User(
        username='admin',
        email='admin@example.com',
        password_hash=generate_password_hash('admin123'),
        is_admin=True
    )
    db.session.add(admin)
    db.session.commit()
    print("Admin user created!")
```

### 6. (Optional) Seed Sample Tickets

To populate the database with sample tickets for testing:

```bash
python seed_tickets.py
```

## Running the Application

### Development Mode (Local Machine)

Make sure your virtual environment is activated, then run:

```bash
python flask_employee_portal_app.py
```

The application will start on `http://127.0.0.1:5004/`

**Note**: Keep the virtual environment activated while running the application.

### Server Deployment (Company Bare Metal / Production Server)

When deploying on your company's bare metal server with a specific IP and port:

#### Step 1: Configure IP and Port

Open `flask_employee_portal_app.py` and find the last line (line 984):

```python
if __name__ == "__main__":
    with app.app_context():
        bootstrap()
    app.run(host="0.0.0.0", port=5004, debug=True)
```

**Configuration Options:**

- **`host="0.0.0.0"`**: This allows the server to accept connections from any IP address. Keep this as is for server deployment.
- **`port=5004`**: Change this to your desired port number (e.g., 8080, 8000, 5000, etc.)
- **`debug=True`**: Change to `debug=False` for production deployment

**Example Configuration:**

For accessing via `http://192.168.1.100:8080`:
```python
app.run(host="0.0.0.0", port=8080, debug=False)
```

For accessing via `http://10.0.0.50:5000`:
```python
app.run(host="0.0.0.0", port=5000, debug=False)
```

#### Step 2: Run on Server

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate  # Windows

# Run the application
python flask_employee_portal_app.py
```

#### Step 3: Access the Application

Open browser and navigate to:
```
http://YOUR_SERVER_IP:YOUR_PORT
```

Examples:
- `http://192.168.1.100:8080`
- `http://10.0.0.50:5004`
- `http://172.16.0.10:5000`

#### Important Notes for Server Deployment:

1. **Firewall Configuration**: Ensure the port is open in your server's firewall
   ```bash
   # Ubuntu/Debian
   sudo ufw allow 8080/tcp
   
   # CentOS/RHEL
   sudo firewall-cmd --permanent --add-port=8080/tcp
   sudo firewall-cmd --reload
   ```

2. **Security Settings**: For production, update in `flask_employee_portal_app.py`:
   ```python
   # Change debug to False (around line 984)
   app.run(host="0.0.0.0", port=8080, debug=False)
   
   # Ensure secure cookies (around line 38-39)
   app.config['SESSION_COOKIE_SECURE'] = True  # Only if using HTTPS
   ```

3. **Run as Background Service**: To keep it running after logout:
   ```bash
   # Using nohup
   nohup python flask_employee_portal_app.py > app.log 2>&1 &
   
   # Using screen
   screen -S employee-portal
   python flask_employee_portal_app.py
   # Press Ctrl+A then D to detach
   ```

### Production Mode with Gunicorn (Recommended for Production)

For better performance and stability on production servers:

```bash
# Install Gunicorn
pip install gunicorn

# Run with Gunicorn
gunicorn -w 4 -b 0.0.0.0:8080 flask_employee_portal_app:app

# With more options
gunicorn -w 4 -b 0.0.0.0:8080 --access-logfile access.log --error-logfile error.log flask_employee_portal_app:app
```

**Gunicorn Configuration:**
- `-w 4`: Number of worker processes (use 2-4 × number of CPU cores)
- `-b 0.0.0.0:8080`: Bind to IP and port
- `--access-logfile`: Log HTTP requests
- `--error-logfile`: Log errors

**Access via**: `http://YOUR_SERVER_IP:8080`

### Setting Up as a Systemd Service (Linux Servers)

Create a service file for automatic startup:

```bash
sudo nano /etc/systemd/system/employee-portal.service
```

Add the following configuration:
```ini
[Unit]
Description=Employee Portal Flask Application
After=network.target

[Service]
User=your_username
WorkingDirectory=/path/to/employee-management
Environment="PATH=/path/to/employee-management/venv/bin"
ExecStart=/path/to/employee-management/venv/bin/python flask_employee_portal_app.py

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable employee-portal
sudo systemctl start employee-portal
sudo systemctl status employee-portal
```

## Default Credentials

After setting up, you can create your own admin account. For testing purposes:

- **Admin**: 
  - Username: `admin`
  - Password: `admin123` (change this!)

- **Employee**: Create through admin dashboard

## Usage

### Admin Features
1. **Dashboard**: View system statistics and recent activities
2. **Employee Management**: Add, edit, and remove employee accounts
3. **Ticket Management**: View, approve, or reject employee tickets
4. **User Management**: Manage user accounts and roles

### Employee Features
1. **Dashboard**: View personal information and ticket status
2. **Raise Ticket**: Submit new ticket requests for equipment/access
3. **View Details**: Check personal employment details
4. **Track Tickets**: Monitor status of submitted tickets

## Configuration

Key configuration options in `flask_employee_portal_app.py`:

```python
# Security
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change in production!

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

# Session
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
```

### Environment Variables

For production, set these environment variables:

- `SECRET_KEY`: A secure random key for session management
- `DATABASE_URL`: Database connection string (if not using SQLite)

## Security Notes

⚠️ **Important for Production:**

1. Change the `SECRET_KEY` to a secure random value
2. Enable HTTPS and set `SESSION_COOKIE_SECURE = True`
3. Use a production database (PostgreSQL, MySQL) instead of SQLite
4. Set strong password policies
5. Implement rate limiting for login attempts
6. Regular security audits and updates

## Development

### File Structure

- **Models**: User, Ticket, Department (defined in main app file)
- **Routes**: Organized by role (admin, employee, auth)
- **Templates**: Modular structure with base layouts and reusable components
- **Static Files**: CSS and JavaScript for frontend functionality

### Database Schema

**User Table:**
- id (Primary Key)
- username (Unique)
- email (Unique)
- password_hash
- is_admin (Boolean)
- Department and personal information

**Ticket Table:**
- id (Primary Key)
- employee_id (Foreign Key to User)
- item (Equipment/Access type)
- reason (Description)
- status (Pending/Approved/Rejected)
- timestamps

## Troubleshooting

### Virtual Environment Issues

If activation fails on Windows PowerShell:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Database Issues

To reset the database:
```bash
# Delete the database file
rm instance/app.db

# Restart the application to recreate
python flask_employee_portal_app.py
```

### Port Already in Use

If port 5000 is busy:
```python
# In flask_employee_portal_app.py, change the port:
if __name__ == '__main__':
    app.run(debug=True, port=5001)
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is open source and available under the MIT License.

## Contact

For issues, questions, or contributions, please open an issue on GitHub.

---

**Note**: This application is designed for educational and internal use. Ensure proper security measures are in place before deploying to production.

## 🎯 Server Configuration - Visual Guide

### Where to Change IP and Port Configuration

In `flask_employee_portal_app.py`, scroll to the **bottom of the file** (line 984):

```python
# CONFIGURATION LOCATION - Line 984
# ====================================

if __name__ == "__main__":
    with app.app_context():
        bootstrap()
    
    # 👇 CHANGE THESE VALUES FOR YOUR SERVER 👇
    app.run(
        host="0.0.0.0",    # Keep as 0.0.0.0 to accept external connections
        port=5004,         # 🔧 CHANGE THIS to your desired port (e.g., 8080)
        debug=True         # 🔧 CHANGE THIS to False for production
    )
```

### Configuration Examples

#### Example 1: Port 8080 (Production)
```python
app.run(host="0.0.0.0", port=8080, debug=False)
```
Access: `http://192.168.1.100:8080` (replace with your server IP)

#### Example 2: Port 5000 (Production)
```python
app.run(host="0.0.0.0", port=5000, debug=False)
```
Access: `http://10.0.0.50:5000` (replace with your server IP)

#### Example 3: Port 3000 (Production)
```python
app.run(host="0.0.0.0", port=3000, debug=False)
```
Access: `http://172.16.0.10:3000` (replace with your server IP)

### Common Port Numbers

| Port | Usage | Example Access URL |
|------|-------|-------------------|
| 5000 | Flask default | `http://YOUR_IP:5000` |
| 5004 | Current default | `http://YOUR_IP:5004` |
| 8000 | Common alternative | `http://YOUR_IP:8000` |
| 8080 | HTTP alternative | `http://YOUR_IP:8080` |
| 3000 | Development servers | `http://YOUR_IP:3000` |

### Verification Steps

After starting the application, you should see:
```
 * Running on http://0.0.0.0:YOUR_PORT
 * Running on http://127.0.0.1:YOUR_PORT
 * Running on http://YOUR_SERVER_IP:YOUR_PORT
```

### Troubleshooting

**Problem**: Cannot access from other machines
- **Solution**: Ensure `host="0.0.0.0"` (not `127.0.0.1`)
- **Solution**: Check firewall allows the port

**Problem**: Port already in use
- **Solution**: Change to a different port number
- **Solution**: Kill the process using that port:
  ```bash
  # Linux
  sudo lsof -ti:8080 | xargs kill -9
  
  # Windows
  netstat -ano | findstr :8080
  taskkill /PID <PID_NUMBER> /F
  ```

**Problem**: Connection refused
- **Solution**: Ensure application is running
- **Solution**: Check server IP address is correct
- **Solution**: Verify port matches configuration

