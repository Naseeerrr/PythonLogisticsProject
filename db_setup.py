import sqlite3
import bcrypt

# Connect to SQLite database (creates the file if it doesn't exist)
conn = sqlite3.connect('ksu_logistics.db')
cursor = conn.cursor()

# Create the ⁠ users ⁠ table with `otp_secret`
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    user_class TEXT NOT NULL CHECK (user_class IN ('Student', 'Faculty', 'Employee', 'Admin', 'Courier')),
    user_id TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    phone TEXT NOT NULL,
    otp_secret TEXT  -- Column to store OTP secret for 2FA
);
""")

# Create the ⁠ logistics_offices ⁠ table
cursor.execute("""
CREATE TABLE IF NOT EXISTS logistics_offices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    office_id TEXT UNIQUE NOT NULL,
    office_name TEXT NOT NULL
);
""")

# Create the ⁠ packages ⁠ table
cursor.execute("""
CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id TEXT NOT NULL,
    receiver_id TEXT NOT NULL,
    dimensions TEXT NOT NULL,
    weight REAL NOT NULL,
    tracking_number TEXT UNIQUE NOT NULL,
    timestamp TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('In Transit', 'Accepted', 'Delivered')),
    logistics_office_id TEXT NOT NULL,
    FOREIGN KEY (logistics_office_id) REFERENCES logistics_offices(office_id)
);
""")

# Insert sample logistics offices
cursor.executemany("""
INSERT OR IGNORE INTO logistics_offices (office_id, office_name)
VALUES (?, ?);
""", [
    ("LOG001", "Main Campus Office"),
    ("LOG002", "North Campus Office"),
    ("LOG003", "South Campus Office")
])

# Add a sample admin user with hashed password and a random TOTP secret
import pyotp  # Importing pyotp to generate the OTP secret

otp_secret = pyotp.random_base32()  # Generate a random base32 secret for TOTP
hashed_password = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt())
cursor.execute("""
INSERT OR IGNORE INTO users (first_name, last_name, user_class, user_id, password_hash, email, phone, otp_secret)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);
""", ("Admin", "User", "Admin", "ADM001", hashed_password, "admin@ksu.edu.sa", "0500000000", otp_secret))

# Add otp_secret column to users table if it doesn't exist
try:
    cursor.execute("ALTER TABLE users ADD COLUMN otp_secret TEXT")
    conn.commit()
except sqlite3.OperationalError as e:
    if "duplicate column name" in str(e):
        print("Column otp_secret already exists.")

# Commit changes and close the connection
conn.commit()
conn.close()

print("Database setup completed successfully!")