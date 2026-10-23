
from database import get_connection
from auth import hash_password

username = input("Enter admin username: ")
password = input("Enter admin password: ")

connection = get_connection()

try:
    existing = connection.execute(
        "SELECT id FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if existing:
        print("Username already exists!")
    else:
        connection.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, hash_password(password), "admin")
        )
        connection.commit()
        print("Admin user created successfully!")
finally:
    connection.close()
