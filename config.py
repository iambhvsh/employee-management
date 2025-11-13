import os

CONFIG = {
    "COMPANY_NAME": os.environ.get("COMPANY_NAME", "Company Name"),
    
    # Email Configuration (SMTP for Outlook) - Use environment variables
    "MAIL_SERVER": os.environ.get("MAIL_SERVER", "smtp.office365.com"),
    "MAIL_PORT": int(os.environ.get("MAIL_PORT", "587")),
    "MAIL_USE_TLS": os.environ.get("MAIL_USE_TLS", "True").lower() == "true",
    "MAIL_USERNAME": os.environ.get("MAIL_USERNAME", ""),
    "MAIL_PASSWORD": os.environ.get("MAIL_PASSWORD", ""),
    "MAIL_DEFAULT_SENDER": os.environ.get("MAIL_DEFAULT_SENDER", ""),
    
    # Asset Types
    "ASSET_TYPES": ["Laptop", "Charger", "Keyboard", "Mouse", "Headset", "Monitor", "Docking Station", "Mobile Device", "Bag"],
    
    # Departments
    "DEPARTMENTS": ["Engineering", "Human Resources", "Finance", "Marketing", "Sales", "Operations", "IT", "Administration"],
    
    "TICKET_STATUSES": ["Pending", "Approved", "Rejected"],
    "TICKET_GROUPS": {
        "ITEMS": [
            "KEYBOARD",
            "MOUSE",
            "LAPTOP ISSUE",
            "CHARGER",
            "HEADSET",
            "RAM CHANGE",
            "SCREEN ISSUE",
            "KEYPAD ISSUE",
            "TOUCHPAD ISSUE",
        ],
        "ACCESS": ["VPN ACCESS", "EMAIL ACCESS", "BIOMETRIC ACCESS"],
        "ISSUES": ["SOFTWARE ISSUE", "NETWORK ISSUE", "PERFORMANCE ISSUE"],
        "OTHER": ["OTHER"],
    },
    "SERVICE_REQUEST_TYPES": {
        "DevOps": ["Add Port", "Add VPN", "Add Route", "Add Firewall"],
        "Developer": ["GitHub Access Request"],
    },
    "LABELS": {
        "SIDEBAR_SECTION_ADMIN": "Admin",
        "SIDEBAR_SECTION_EMPLOYEE": "Employee",
        "NAV_DASHBOARD": "Dashboard",
        "NAV_EMPLOYEES": "Employees",
        "NAV_MANAGE": "Manage",
        "NAV_USER_MANAGEMENT": "User Management",
        "NAV_TICKETS": "Tickets",
        "NAV_SERVICE_REQUESTS": "Service Requests",
        "NAV_GITHUB_ACCESS": "GitHub Access",
        "NAV_ASSETS": "Assets Inventory",
        "NAV_ONBOARDING": "Onboarding",
        "NAV_EXIT": "Exit Process",
        "NAV_MY_DETAILS": "My Details",
        "NAV_RAISE_TICKET": "Raise Ticket",
        "NAV_SIGN_OUT": "Sign Out",
        "LOGIN_SUBTITLE": "Sign in to continue to your workspace",
    },
    "USERS": [
        {
            "name": os.environ.get("ADMIN_NAME"),
            "email": "admin@company.com",
            "phone": "1234567890",
            "department": "Administration",
            "Admin": True,
            "password": os.environ.get("ADMIN_PASSWORD"),
            "assets": {
                "laptop": "MBP001",
                "charger": "CRR001",
                "keyboard": "KB001",
                "mouse": "MUE001",
                "headset": "HS001",
            },
        }
    ],
}