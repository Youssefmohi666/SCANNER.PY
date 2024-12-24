import random
import re
import socket
import nmap
import time
from flask import *
import smtplib
import os
import webbrowser
from cryptography.fernet import Fernet
import base64
import hashlib

# 1. التحقق من صحة البريد الإلكتروني
def email_is_valid(email):
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

# دالة لتوليد مفتاح التشفير باستخدام كلمة مرور
def generate_key(password: str) -> bytes:
    # استخدام عملية "hashing" لتحويل كلمة المرور إلى مفتاح مناسب للتشفير
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

# دالة لتشفير النصوص
def encrypt_data(data: str, password: str) -> str:
    key = generate_key(password)  # توليد المفتاح باستخدام كلمة المرور
    fernet = Fernet(key)  # إنشاء الكائن الذي سيقوم بالتشفير
    encrypted_data = fernet.encrypt(data.encode())  # تشفير البيانات
    return encrypted_data.decode()  # إرجاع النص المشفر كـ string

# دالة لفك التشفير
def decrypt_data(encrypted_data: str, password: str) -> str:
    key = generate_key(password)  # توليد المفتاح باستخدام كلمة المرور
    fernet = Fernet(key)  # إنشاء الكائن الذي سيقوم بفك التشفير
    decrypted_data = fernet.decrypt(encrypted_data.encode())  # فك تشفير البيانات
    return decrypted_data.decode()  # إرجاع النص المفكوك

# 2. تسجيل المعلومات في ملف النصي
def save_info_to_file(name, age, email, password):
    try:
        # تشفير البيانات قبل حفظها
        encrypted_email = encrypt_data(email, "11223344")
        encrypted_password = encrypt_data(password, "11223344")
        
        with open("info.txt", "a") as file:
            file.write(f"Name: {name}\n")
            file.write(f"Age: {age}\n")
            file.write(f"Email: {encrypted_email}\n")  # حفظ البريد المشفر
            file.write(f"Password: {encrypted_password}\n")  # حفظ كلمة المرور المشفرة
            file.write("-------------------------------\n")
        print("Information has been saved successfully!")
    except Exception as e:
        print(f"An error occurred while saving information: {e}")

# 3. عملية تسجيل الدخول
def login():
    try:
        name = str(input('Enter your name: '))
        age = int(input("Enter your age: "))
        
        user_email = input("Enter your email address: ")
        if not email_is_valid(user_email):
            print("Invalid email format. Please try again.")
            return

        password = input("Enter your password: ")

        # حفظ البيانات المشفرة في الملف
        save_info_to_file(name, age, user_email, password)

    except ValueError:
        print('Value error: Please enter valid information.')
    return f"Login successful. Welcome {name}!"

# 4. الحصول على عنوان الـ IP من اسم المجال (Domain)
def get_ip_of_host():
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

# 5. فحص البورتات لجهاز معين
def scan_ports(target_ip):
    try:
        # إنشاء ماسح nmap
        nm = nmap.PortScanner()

        # فحص البورتات
        print(f"Scanning ports on {target_ip}...")
        nm.scan(hosts=target_ip, arguments='-p 1-65535')  # فحص البورتات من 1 إلى 65535

        # عرض النتائج
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

# 6. فحص الشبكة بأكملها
def scan_network():
    try:
        # إنشاء ماسح nmap
        nm = nmap.PortScanner()

        # إدخال النطاق (مثل 192.168.1.0/24)
        network_range = input("Enter the network range to scan (e.g., 192.168.1.0/24): ")

        # فحص الشبكة
        print(f"Scanning network range: {network_range}...")
        nm.scan(hosts=network_range, arguments='-sP')  # -sP هو فحص IP فقط بدون فحص البورتات

        # عرض النتائج
        if nm.all_hosts():
            print(f"Scan results for network {network_range}:")
            for host in nm.all_hosts():
                print(f"Host: {host} ({nm[host].hostname()})")
                print(f"State: {nm[host].state()}")
        else:
            print("No hosts found in the scan.")
    except Exception as e:
        print(f"An error occurred while scanning: {str(e)}")

# 7. فحص IP
def scan_ip():
    try:
        target_ip = input("Enter the IP address to scan: ")
        scan_ports(target_ip)
    except Exception as e:
        print(f"Error scanning IP: {e}")

# 8. قائمة الاختيارات للمستخدم
def show_menu():
    time.sleep(2)
    print("\n--- Network Scanner ---")
    print("1. Scan a specific IP")
    print("2. Scan a network range")
    print("3. Get IP address of a domain")
    print("4. Exit")

# 9. البرنامج الرئيسي
def main():
    while True:
        show_menu()
        choice = input("Enter your choice: ")

        if choice == "1":
            scan_ip()  # فحص IP معين
        elif choice == "2":
            scan_network()  # فحص نطاق الشبكة
        elif choice == "3":
            get_ip_of_host()  # الحصول على عنوان IP من اسم النطاق
        elif choice == "4":
            print("Exiting program.")
            break  # الخروج من البرنامج
        else:
            print("Invalid choice, please try again.")
if __name__ == "__main__":
  login()  # نبدأ بتسجيل الدخول أولاً
  main()  # بعد ذلك نعرض قائمة الاختيارات   