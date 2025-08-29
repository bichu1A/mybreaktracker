from app import db, User

# Check if admin exists
admin = User.query.filter_by(username='admin').first()
if admin:
    print("Admin user already exists:", admin)
else:
    admin = User(username='admin', role='admin')
    admin.set_password('admin123')  # Change password if you want
    db.session.add(admin)
    db.session.commit()
    print("Admin user created successfully.")
