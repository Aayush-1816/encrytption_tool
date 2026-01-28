# 🔐 Python Cryptography & Password Security Toolkit

A cross-platform command-line security tool for **file encryption/decryption, password hashing, and verification**, built using industry-standard Python security libraries.

This project demonstrates practical implementation of **core cryptographic and password security concepts** used in cybersecurity.

---

## 🚀 Features

- 🔒 **File Encryption & Decryption**
  - Uses **Fernet symmetric encryption** from the `cryptography` library
  - Works with documents, images, videos, and other file types

- 🔑 **Secure Key Generation & Storage**
  - Automatically generates encryption keys
  - Designed to prevent plaintext exposure

- 🧂 **Password Hashing**
  - Uses **bcrypt** with salting for strong password protection

- ✅ **Password Verification**
  - Validates user input against stored hashed passwords

- 📄 **Operation Logging**
  - Records tool activity in a centralized `usage.log` file

- 🧰 **Menu-Driven CLI Interface**
  - Easy-to-use terminal interface for all operations

- 💻 **Cross-Platform Support**
  - Works on Windows, Linux, and macOS

---

## 🛠️ Technologies Used

| Purpose | Tool/Library |
|--------|--------------|
Encryption | `cryptography` (Fernet) |
Password Security | `bcrypt` |
Language | Python 3 |

---

## ⚙️ Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/Aayush-1816/python-cryptography-toolkit.git
cd python-cryptography-toolkit
