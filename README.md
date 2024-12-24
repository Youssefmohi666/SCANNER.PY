# Network Scanner and Information Encryptor

#### Video Demo: <URL_HERE>
#### Description:

The Network Scanner and Information Encryptor project is a Python-based tool that allows users to securely log in, encrypt their sensitive information, scan networks, and perform other network-related tasks. The project implements several functions such as email validation, IP address retrieval from domain names, port scanning, and network scanning. Additionally, it provides a feature for encrypting and saving user data, and it ensures that the user can later decrypt it by entering a correct password.

## Features:
- **Email Validation**: Check if an email is correctly formatted using regular expressions.
- **User Information Encryption**: Encrypt sensitive data (such as email and password) before saving it into a text file.
- **Network Scanning**: Scan specific IP addresses or entire network ranges for open ports.
- **Domain Name Resolution**: Retrieve the IP address of a given domain name.
- **File Compression**: Compress the `info.txt` file to a `.zip` format to enhance security.
- **Data Decryption**: Decrypt the stored encrypted data using a password.

## Files in the Project:
- **project.py**: The main Python file containing all the functions, including the main program loop and network scanning logic.
- **test_project.py**: A file that contains tests for the functions implemented in the project.
- **requirements.txt**: A text file listing the required Python packages for this project.

## Functionality Overview:

1. **User Login**: The user enters their name, age, email, and password. This information is encrypted before being saved to a text file (`info.txt`).
2. **Network Scanning**: The user can scan a specific IP or a network range for open ports using the `nmap` module.
3. **Domain Name Resolution**: The user can enter a domain name, and the program will retrieve its associated IP address.
4. **File Compression and Decryption**: The `info.txt` file is encrypted and can be compressed into a `.zip` file. The user can later decrypt the file by providing a password.

### Requirements:
This project uses several Python libraries to implement the functionalities:

- **Flask**: For building a web interface (optional for future expansion).
- **Cryptography**: To handle encryption and decryption operations.
- **Nmap**: For scanning ports and networks.
- **Socket**: For handling domain name resolution and IP address retrieval.

### Installation:
1. Clone this repository:
    ```bash
    git clone <repository_url>
    ```
2. Navigate to the project directory:
    ```bash
    cd <project_directory>
    ```
3. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

### Usage:
1. Run the main program by executing:
    ```bash
    python project.py
    ```
2. Follow the on-screen prompts to log in, scan IPs, or perform other operations.

### Example Usage:
1. **Login**: Enter your name, age, email, and password.
2. **Network Scan**: Choose to scan a specific IP or a network range.
3. **Decryption**: Use the correct password to decrypt the `info.txt` file and view the stored information.

### License:
This project is licensed under the MIT License.
