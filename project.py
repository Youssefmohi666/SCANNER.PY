import random
import re
import socket
import nmap
import time
from flask import Flask, request
import smtplib
import os
import webbrowser
from cryptography.fernet import Fernet
import base64
import hashlib

# 1. Email Validation Function
def email_is_valid(email):
    """Validate email format using regex."""
    pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    print('Checking if the email is written correctly...')
    time.sleep(1)
    if re.match(pattern, email):
        print('-------------------------------------------')
        time.sleep(2)
        return True
    else:
        print('-------------------------------------------')
        time.sleep(2)
        return False

# Generate encryption key from password
def generate_key(password: str) -> bytes:
    """Generate an encryption key based on the provided password."""
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

# Encrypt data
def encrypt_data(data: str, password: str) -> str:
    """Encrypt data using a password."""
    key = generate_key(password)  # Generate key using the password
    fernet = Fernet(key)  # Create the encryption object
    encrypted_data = fernet.encrypt(data.encode())  # Encrypt the data
    return encrypted_data.decode()  # Return encrypted data as string

# Decrypt data
def decrypt_data(encrypted_data: str, password: str) -> str:
    """Decrypt the encrypted data using the password."""
    key = generate_key(password)  # Generate key using the password
    fernet = Fernet(key)  # Create the decryption object
    decrypted_data = fernet.decrypt(encrypted_data.encode())  # Decrypt the data
    return decrypted_data.decode()  # Return the decrypted data

# 2. Save user information to a file
def save_info_to_file(name, age, email, password):
    """Save encrypted user information to a text file."""
    try:
        # Encrypt email and password before saving
        encrypted_email = encrypt_data(email, "11223344")
        encrypted_password = encrypt_data(password, "11223344")
        
        with open("info.txt", "a") as file:
            file.write(f"Name: {name}\n")
            file.write(f"Age: {age}\n")
            file.write(f"Email: {encrypted_email}\n")  # Save encrypted email
            file.write(f"Password: {encrypted_password}\n")  # Save encrypted password
            file.write("-------------------------------\n")
        print("Information has been saved successfully!")
    except Exception as e:
        print(f"An error occurred while saving information: {e}")

# 3. Login process
def login():
    """Handle user login and input validation."""
    try:
        name = str(input('Enter your name: '))
        age = int(input("Enter your age: "))
        
        user_email = input("Enter your email address: ")
        if not email_is_valid(user_email):
            print("Invalid email format. Please try again.")
            return

        password = input("Enter your password: ")

        # Save the encrypted data to a file
        save_info_to_file(name, age, user_email, password)

    except ValueError:
        print('Value error: Please enter valid information.')
    return f"Login successful. Welcome {name}!"

# Open and decrypt information stored in info.txt
def open_and_decrypt_info():
    """Open and decrypt information stored in info.txt"""
    try:
        with open("info.txt", "r") as file:
            lines = file.readlines()
            
            for line in lines:
                if "Email" in line or "Password" in line:
                    encrypted_data = line.split(":")[1].strip()
                    if "Email" in line:
                        decrypted_data = decrypt_data(encrypted_data, "11223344")
                        print(f"Decrypted Email: {decrypted_data}")
                    elif "Password" in line:
                        decrypted_data = decrypt_data(encrypted_data, "11223344")
                        print(f"Decrypted Password: {decrypted_data}")
                else:
                    print(line.strip())
    except FileNotFoundError:
        print("File 'info.txt' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Function to modify name or email after asking for password
def modify_user_info():
    """Allow the user to modify name or email after validating password."""
    password = input("Enter the password to access the file (Password: 11223344): ")
    
    if password != "11223344":
        print("Invalid password. Access denied.")
        return

    try:
        with open("info.txt", "r") as file:
            lines = file.readlines()

        # Display the current info for modification
        print("Current information in info.txt:")
        for line in lines:
            print(line.strip())

        # Allow user to modify name or email
        option = input("Do you want to modify (1) Name or (2) Email? Enter your choice: ")

        if option == "1":
            new_name = input("Enter the new name: ")
            # Modify the name in the file
            lines[0] = f"Name: {new_name}\n"
        elif option == "2":
            new_email = input("Enter the new email: ")
            if not email_is_valid(new_email):
                print("Invalid email format.")
                return
            # Encrypt and modify the email in the file
            encrypted_email = encrypt_data(new_email, "11223344")
            lines[2] = f"Email: {encrypted_email}\n"
        else:
            print("Invalid option. No changes were made.")
            return

        # Write the modified information back to the file
        with open("info.txt", "w") as file:
            file.writelines(lines)

        print("Information updated successfully.")
    
    except FileNotFoundError:
        print("File 'info.txt' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# 4. Get IP address from domain name
def get_ip_of_host():
    """Retrieve the IP address of a given domain name."""
    try:
        domain_name = input("Enter the domain name: ")
        pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
        if re.match(pattern, domain_name):
            ip_of_domain = socket.gethostbyname(domain_name)
            print(f"THE IP ADDRESS OF {domain_name} IS [{ip_of_domain}]")
        else:
            print("Invalid domain name format.")
    except socket.gaierror:
        return "Error: Unable to resolve the domain."
    return "IP retrieval completed."

# 5. Scan ports on a specific IP address
def scan_ports(target_ip):
    """Scan open ports on the given IP address."""
    try:
        # Create a PortScanner object
        nm = nmap.PortScanner()

        # Scan ports
        print(f"Scanning ports on {target_ip}...")
        nm.scan(hosts=target_ip, arguments='-p 1-65535')  # Scan ports 1 to 65535

        # Display results
        if nm.all_hosts():
            for host in nm.all_hosts():
                print(f"Host: {host} ({nm[host].hostname()})")
                print(f"State: {nm[host].state()}")
                for proto in nm[host].all_protocols():
                    print(f"Protocol: {proto}")
                    lport = nm[host][proto].keys()
                    for port in lport:
                        print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")
        else:
            print("No hosts found in the scan.")
    except Exception as e:
        print(f"An error occurred while scanning: {str(e)}")

# 6. Scan a network range
def scan_network():
    """Scan a given network range for active hosts."""
    try:
        # Create a PortScanner object
        nm = nmap.PortScanner()

        # Get the network range (e.g., 192.168.1.0/24)
        network_range = input("Enter the network range to scan (e.g., 192.168.1.0/24): ")

        # Scan the network
        print(f"Scanning network range: {network_range}...")
        nm.scan(hosts=network_range, arguments='-sP')  # -sP performs a simple ping scan

        # Display results
        if nm.all_hosts():
            print(f"Scan results for network {network_range}:")
            for host in nm.all_hosts():
                print(f"Host: {host} ({nm[host].hostname()})")
                print(f"State: {nm[host].state()}")
        else:
            print("No hosts found in the scan.")
    except Exception as e:
        print(f"An error occurred while scanning: {str(e)}")

# 7. Scan a specific IP address
def scan_ip():
    """Scan a specific IP address."""
    try:
        target_ip = input("Enter the IP address to scan: ")
        scan_ports(target_ip)
    except Exception as e:
        print(f"Error scanning IP: {e}")

# 8. Display menu options
def show_menu():
    """Display menu options to the user."""
    print("\n--- Network Scanner ---")
    print("1. Scan a specific IP")
    print("2. Scan a network range")
    print("3. Get IP address of a domain")
    print("4. Open and Decrypt info.txt")
    print("5. Modify user info (Name/Email)")
    print("6. Exit")

# Main program
def main():
    while True:
        show_menu()
        choice = input("Enter your choice: ")

        if choice == "1":
            scan_ip()
        elif choice == "2":
            scan_network()
        elif choice == "3":
            get_ip_of_host()
        elif choice == "4":
            open_and_decrypt_info()  # Open and decrypt info.txt
        elif choice == "5":
            modify_user_info()  # Modify user information (Name/Email)
        elif choice == "6":
            print("Exiting program.")
            break
        else:
            print("Invalid choice, please try again.")
    login()  # Start by logging in
    main()  # After login, show the main menu

# Run the main program
if __name__ == "__main__":
    login()
    main()
