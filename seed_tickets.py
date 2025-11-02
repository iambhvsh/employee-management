"""Seed sample tickets for testing and development"""

from flask_employee_portal_app import app, db, User, Ticket

with app.app_context():
    # Get all employees from database
    employees = User.query.filter_by(is_admin=False).all()

    if employees:

        tickets_data = [
            {
                'employee': employees[0],
                'item': 'LAPTOP ISSUE',
                'reason': 'Screen flickering intermittently, needs inspection',
                'status': 'Pending'
            },
            {
                'employee': employees[0],
                'item': 'VPN ACCESS',
                'reason': 'Need VPN access for remote work setup',
                'status': 'Approved'
            },
            {
                'employee': employees[1] if len(employees) > 1 else employees[0],
                'item': 'MOUSE',
                'reason': 'Current mouse is not working properly, left click issue',
                'status': 'Pending'
            },
            {
                'employee': employees[2] if len(employees) > 2 else employees[0],
                'item': 'KEYBOARD',
                'reason': 'Few keys are not responding, need replacement',
                'status': 'Rejected'
            },
        ]

        for idx, ticket_data in enumerate(tickets_data):
            ticket = Ticket(
                employee_id=ticket_data['employee'].id,
                item=ticket_data['item'],
                reason=ticket_data['reason'],
                status=ticket_data['status']
            )
            db.session.add(ticket)

        db.session.commit()
        print(f"✅ Created {len(tickets_data)} sample tickets successfully!")
    else:
        print("❌ No employees found. Please ensure employees exist in the database.")
