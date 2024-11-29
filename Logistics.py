from tkinter import *
from tkinter import messagebox
import sqlite3
import bcrypt
import random
import time
import csv
import pyotp
import qrcode
from PIL import Image
from tkintermapview import TkinterMapView

# Connect to SQLite database
conn = sqlite3.connect('ksu_logistics.db')
cursor = conn.cursor()

# Ensure otp_secret column exists in the users table
try:
    cursor.execute("ALTER TABLE users ADD COLUMN otp_secret TEXT")
    conn.commit()
except sqlite3.OperationalError as e:
    if "duplicate column name" in str(e):
        print("Column otp_secret already exists.")

# Hash Password Utility
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

# Main Window
def main_window():
    def open_signup():
        main_root.destroy()  # Close the main menu
        signup_window()      # Open the Sign-Up window

    def open_login():
        main_root.destroy()  # Close the main menu
        login_window()       # Open the Login window

    main_root = Tk()
    main_root.title("KSU Logistics - Main Menu")
    main_root.geometry("400x300")
    main_root.configure(bg="#f0f8ff")  # Light blue background

    # Title
    Label(
        main_root,
        text="Welcome to KSU Logistics System",
        font=("Arial", 16),
        bg="#f0f8ff",
        fg="#333333"
    ).pack(pady=20)

    # Sign-Up Button
    Button(
        main_root,
        text="Sign Up",
        font=("Arial", 12),
        bg="white",
        fg="black",
        width=20,
        command=open_signup
    ).pack(pady=10)

    # Login Button
    Button(
        main_root,
        text="Login",
        font=("Arial", 12),
        bg="white",
        fg="black",
        width=20,
        command=open_login
    ).pack(pady=10)

    # Footer
    Label(
        main_root,
        text="Designed for KSU Community",
        font=("Arial", 10),
        bg="#f0f8ff",
        fg="#555555"
    ).pack(side=BOTTOM, pady=10)

    main_root.mainloop()


# Sign-Up Window
def signup_window():
    def submit_signup():
     first_name = entry_first_name.get()
     last_name = entry_last_name.get()
     user_class = user_class_var.get()
     user_id = entry_user_id.get()
     password = entry_password.get()
     email = entry_email.get()
     phone = entry_phone.get()

     # Validation
     if not all([first_name, last_name, user_class, user_id, password, email, phone]):
        messagebox.showerror("Error", "All fields are required!")
        return

     if len(password) < 6:
        messagebox.showerror("Error", "Password must be at least 6 characters long!")
        return

     if user_class not in ["Student", "Faculty", "Employee", "Admin", "Courier"]:
        messagebox.showerror("Error", "Invalid user class!")
        return

     if not user_id.isdigit() or not (len(user_id) == 10 or len(user_id) == 6):
        messagebox.showerror("Error", "User ID must be 10 digits for Students or 6 digits for others!")
        return

     if not email.endswith("@ksu.edu.sa"):
        messagebox.showerror("Error", "Email must end with @ksu.edu.sa!")
        return

     if not phone.startswith("05") or len(phone) != 10 or not phone.isdigit():
        messagebox.showerror("Error", "Phone number must be in the format 05XXXXXXXX!")
        return

     # Generate OTP Secret
     otp_secret = pyotp.random_base32()

     # Generate QR Code
     totp = pyotp.TOTP(otp_secret)
     qr_data = totp.provisioning_uri(name=email, issuer_name="KSU Logistics")
     qr_img = qrcode.make(qr_data)
     qr_img.save("otp_qr.png")  # Save QR for the user to scan

     # Save User with OTP Secret
     try:
        hashed_password = hash_password(password)
        cursor.execute("""
        INSERT INTO users (first_name, last_name, user_class, user_id, password_hash, email, phone, otp_secret)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (first_name, last_name, user_class, user_id, hashed_password, email, phone, otp_secret))
        conn.commit()

        # Show QR Code
        qr_img.show()  # Opens the QR code image
        messagebox.showinfo("Success", "Sign-Up Successful! Scan the QR code using Google Authenticator or Authy.")
     except sqlite3.IntegrityError:
        messagebox.showerror("Error", "User ID or Email already exists!")

    def go_back():
        signup.destroy()
        main_window()

    signup = Tk()
    signup.title("KSU Logistics - Sign-Up")
    signup.geometry("400x400")

    Label(signup, text="First Name").grid(row=0, column=0, padx=10, pady=10)
    entry_first_name = Entry(signup)
    entry_first_name.grid(row=0, column=1)

    Label(signup, text="Last Name").grid(row=1, column=0, padx=10, pady=10)
    entry_last_name = Entry(signup)
    entry_last_name.grid(row=1, column=1)

    Label(signup, text="User Class").grid(row=2, column=0, padx=10, pady=10)
    user_class_var = StringVar(signup)
    user_class_var.set("Student")
    OptionMenu(signup, user_class_var, "Student", "Faculty", "Employee", "Admin", "Courier").grid(row=2, column=1)

    Label(signup, text="User ID").grid(row=3, column=0, padx=10, pady=10)
    entry_user_id = Entry(signup)
    entry_user_id.grid(row=3, column=1)

    Label(signup, text="Password").grid(row=4, column=0, padx=10, pady=10)
    entry_password = Entry(signup, show="*")
    entry_password.grid(row=4, column=1)

    Label(signup, text="Email").grid(row=5, column=0, padx=10, pady=10)
    entry_email = Entry(signup)
    entry_email.grid(row=5, column=1)

    Label(signup, text="Phone").grid(row=6, column=0, padx=10, pady=10)
    entry_phone = Entry(signup)
    entry_phone.grid(row=6, column=1)

    Button(signup, text="Submit", command=submit_signup).grid(row=7, column=1, pady=10)
    Button(signup, text="Back", command=go_back).grid(row=8, column=1, pady=10)

    signup.mainloop()

# Login Window
def login_window():
    def login():
     user_id = entry_user_id.get()
     password = entry_password.get()

     if not user_id or not password:
        messagebox.showerror("Error", "All fields are required!")
        return

     try:
        cursor.execute("SELECT user_class, password_hash, otp_secret FROM users WHERE user_id = ?", (user_id,))
        result = cursor.fetchone()

        if result:
            user_class, stored_hash, otp_secret = result
            if bcrypt.checkpw(password.encode(), stored_hash):
                if otp_secret is None:  # User does not have 2FA enabled
                    # Generate a new OTP secret
                    otp_secret = pyotp.random_base32()
                    totp = pyotp.TOTP(otp_secret)
                    qr_data = totp.provisioning_uri(name=user_id, issuer_name="KSU Logistics")
                    qr_img = qrcode.make(qr_data)
                    qr_img.save("otp_qr.png")

                    # Update the database with the new OTP secret
                    cursor.execute("UPDATE users SET otp_secret = ? WHERE user_id = ?", (otp_secret, user_id))
                    conn.commit()

                    # Show the QR code
                    qr_img.show()
                    messagebox.showinfo(
                        "2FA Setup Required",
                        "2FA has been enabled for your account.\nPlease scan the QR code using Google Authenticator or Authy."
                    )
                    return

                # Prompt for OTP if already set up
                otp_window = Toplevel(login_root)
                otp_window.title("Enter OTP")
                otp_window.geometry("300x200")
                otp_window.transient(login_root)
                otp_window.grab_set()

                Label(otp_window, text="Enter OTP").pack(pady=10)
                entry_otp = Entry(otp_window)
                entry_otp.pack(pady=10)

                def verify_otp():
                    otp = entry_otp.get()
                    totp = pyotp.TOTP(otp_secret)
                    if totp.verify(otp):
                        otp_window.destroy()
                        login_root.destroy()
                        if user_class == "Admin":
                            admin_window()
                        elif user_class in ["Student", "Faculty", "Employee"]:
                            user_window(user_id)
                        elif user_class == "Courier":
                            courier_window()
                    else:
                        messagebox.showerror("Error", "Invalid OTP!")

                Button(otp_window, text="Verify", command=verify_otp).pack(pady=10)
            else:
                messagebox.showerror("Error", "Invalid credentials!")
        else:
            messagebox.showerror("Error", "User not found!")

     except Exception as e:
        messagebox.showerror("Error", str(e))

    def go_back():
        login_root.destroy()
        main_window()

    login_root = Tk()
    login_root.title("KSU Logistics - Login")
    login_root.geometry("400x300")

    Label(login_root, text="User ID").grid(row=0, column=0, padx=10, pady=10)
    entry_user_id = Entry(login_root)
    entry_user_id.grid(row=0, column=1)

    Label(login_root, text="Password").grid(row=1, column=0, padx=10, pady=10)
    entry_password = Entry(login_root, show="*")
    entry_password.grid(row=1, column=1)

    Button(login_root, text="Login", command=login).grid(row=2, column=1, pady=10)
    Button(login_root, text="Back", command=go_back).grid(row=3, column=1, pady=10)

    login_root.mainloop()

# Admin Window
def admin_window():
    def create_office():
        office_id = entry_office_id.get()
        office_name = entry_office_name.get()

        if not office_id or not office_name:
            messagebox.showerror("Error", "All fields are required!")
            return

        try:
            cursor.execute("""
            INSERT INTO logistics_offices (office_id, office_name)
            VALUES (?, ?)
            """, (office_id, office_name))
            conn.commit()
            messagebox.showinfo("Success", "Logistics Office Created!")
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Office ID already exists!")

    admin_root = Tk()
    admin_root.title("KSU Logistics - Admin")
    admin_root.geometry("400x400")

    Label(admin_root, text="Office ID").grid(row=0, column=0, padx=10, pady=10)
    entry_office_id = Entry(admin_root)
    entry_office_id.grid(row=0, column=1)

    Label(admin_root, text="Office Name").grid(row=1, column=0, padx=10, pady=10)
    entry_office_name = Entry(admin_root)
    entry_office_name.grid(row=1, column=1)

    Button(admin_root, text="Create Office", command=create_office).grid(row=2, column=1, pady=20)

    admin_root.mainloop()

# User Window
def user_window(user_id):
    def drop_package():
        logistics_office = office_var.get()
        dimensions = entry_dimensions.get()
        weight = entry_weight.get()
        receiver_id = entry_receiver_id.get()

        if not all([logistics_office, dimensions, weight, receiver_id]):
            messagebox.showerror("Error", "All fields are required!")
            return

        try:
            tracking_number = str(random.randint(1000000000000000, 9999999999999999))
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("""
            INSERT INTO packages (sender_id, receiver_id, dimensions, weight, tracking_number, timestamp, status, logistics_office_id)
            VALUES (?, ?, ?, ?, ?, ?, 'In Transit', ?)
            """, (user_id, receiver_id, dimensions, weight, tracking_number, timestamp, logistics_office))
            conn.commit()
            messagebox.showinfo("Success", f"Package dropped! Tracking #: {tracking_number}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    user_root = Tk()
    user_root.title("KSU Logistics - User")
    user_root.geometry("500x400")

    Label(user_root, text="Logistics Office").grid(row=0, column=0, padx=10, pady=10)
    office_var = StringVar(user_root)
    office_var.set("Select Office")

    cursor.execute("SELECT office_id FROM logistics_offices")
    offices = [row[0] for row in cursor.fetchall()]
    OptionMenu(user_root, office_var, *offices).grid(row=0, column=1)

    Label(user_root, text="Dimensions").grid(row=1, column=0, padx=10, pady=10)
    entry_dimensions = Entry(user_root)
    entry_dimensions.grid(row=1, column=1)

    Label(user_root, text="Weight (kg)").grid(row=2, column=0, padx=10, pady=10)
    entry_weight = Entry(user_root)
    entry_weight.grid(row=2, column=1)

    Label(user_root, text="Receiver ID").grid(row=3, column=0, padx=10, pady=10)
    entry_receiver_id = Entry(user_root)
    entry_receiver_id.grid(row=3, column=1)

    Button(user_root, text="Drop Package", command=drop_package).grid(row=4, column=1, pady=20)

    user_root.mainloop()

# Courier Window
def courier_window():
    def update_status(status):
        tracking_number = entry_tracking_number.get()

        if not tracking_number:
            messagebox.showerror("Error", "Tracking number is required!")
            return

        try:
            # Fetch package and logistics office data
            cursor.execute("""
            SELECT p.logistics_office_id, p.receiver_id, o.office_name
            FROM packages p
            JOIN logistics_offices o ON p.logistics_office_id = o.office_id
            WHERE p.tracking_number = ?
            """, (tracking_number,))
            result = cursor.fetchone()

            if not result:
                messagebox.showerror("Error", "Invalid tracking number! Package not found.")
                return

            source_office_id, receiver_id, source_office_name = result

            # Update the package status
            cursor.execute("""
            UPDATE packages
            SET status = ?
            WHERE tracking_number = ?
            """, (status, tracking_number))
            conn.commit()
            messagebox.showinfo("Success", f"Package status updated to '{status}'!")

            # Display the map
            display_map(source_office_name, "Destination Campus Office")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def display_map(source_name, destination_name):
     # Define hardcoded GPS coordinates for known locations
     office_coordinates = {
        "Main Campus Office": (24.7136, 46.6753),  # Example: Riyadh coordinates
        "North Campus Office": (24.7408, 46.6523),
        "South Campus Office": (24.6788, 46.7123),
        "Destination Campus Office": (24.7254, 46.6557)  # Add as required
    }

     # Open a new window for the map
     map_root = Toplevel()
     map_root.title("Package Location Map")
     map_root.geometry("800x600")

     # Add the map widget
     map_widget = TkinterMapView(map_root, width=800, height=600, corner_radius=0)
     map_widget.pack(fill="both", expand=True)

     try:
        # Fetch coordinates for the source and destination
        source_coords = office_coordinates.get(source_name)
        destination_coords = office_coordinates.get(destination_name)

        if not source_coords or not destination_coords:
            raise ValueError("One or both locations have no GPS coordinates.")

        # Set markers at the source and destination
        map_widget.set_marker(source_coords[0], source_coords[1], text=source_name)
        map_widget.set_marker(destination_coords[0], destination_coords[1], text=destination_name)

        # Draw a path between the source and destination
        map_widget.set_path([source_coords, destination_coords])

     except Exception as e:
        messagebox.showerror("Error", f"Unable to display map: {e}")

    # Courier Window GUI
    courier_root = Tk()
    courier_root.title("KSU Logistics - Courier")
    courier_root.geometry("400x300")

    Label(courier_root, text="Tracking Number").grid(row=0, column=0, padx=10, pady=10)
    entry_tracking_number = Entry(courier_root)
    entry_tracking_number.grid(row=0, column=1)

    Button(courier_root, text="Mark as Accepted", command=lambda: update_status("Accepted")).grid(row=1, column=1, pady=10)
    Button(courier_root, text="Mark as Delivered", command=lambda: update_status("Delivered")).grid(row=2, column=1, pady=10)
# 7502535254196661
# 4441005469
# 4441005555
    courier_root.mainloop()

# Start the Main Window
main_window()