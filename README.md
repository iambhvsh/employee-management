# Employee Portal - Flask Application

A role-based employee management system built with Flask that provides separate dashboards for administrators and employees with ticket management capabilities.

## Features

- **Role-Based Access Control**: Separate admin and employee dashboards with different permissions
- **User Authentication**: Secure login system with password hashing
- **Employee Management**: Admin can create, view, and manage employee accounts
- **Ticket System**: Employees can raise tickets, admins can approve/reject them
- **CSRF Protection**: Built-in security against cross-site request forgery
- **Responsive UI**: Clean and modern interface

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

### Development Mode

Make sure your virtual environment is activated, then run:

```bash
python flask_employee_portal_app.py
```

The application will start on `http://127.0.0.1:5000/`

**Note**: Keep the virtual environment activated while running the application.

### Production Mode

For production deployment, use a WSGI server like Gunicorn:

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 flask_employee_portal_app:app
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
