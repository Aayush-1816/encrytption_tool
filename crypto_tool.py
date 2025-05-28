import logging
from cryptography.fernet import Fernet
import bcrypt
import os
import sys

# ====== Logging Setup ====== #
LOG_FILE = "usage.log"

def init_logger():
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

init_logger()

# ====== Banner ====== #
BANNER = r"""
  ____                  _          _____           _ 
 / ___|_ __ _   _ _ __ | |_ ___   |_   _|__   ___ | |
| |   | '__| | | | '_ \| __/ _ \    | |/ _ \ / _ \| |
| |___| |  | |_| | |_) | || (_) |   | | (_) | (_) | |
 \____|_|   \__, | .__/ \__\___/    |_|\___/ \___/|_|
            |___/|_|                                           
"""

# ====== Key Management ====== #
KEY_FILE = "secret.key"

def generate_key():
    try:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        logging.info("Generated new encryption key.")
        return key
    except Exception as e:
        logging.error(f"Failed to generate key: {e}")
        sys.exit("[!] Critical error: Failed to generate key.")

def load_key():
    try:
        if not os.path.exists(KEY_FILE):
            logging.info("Key file not found. Generating new one.")
            return generate_key()
        with open(KEY_FILE, "rb") as f:
            logging.info("Encryption key loaded from file.")
            return f.read()
    except Exception as e:
        logging.error(f"Failed to load key: {e}")
        sys.exit("[!] Critical error: Failed to load key.")

fernet = Fernet(load_key())

# ====== Password Hashing ====== #
def hash_password(password: str) -> bytes:
    try:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt)
        logging.info("Password hashed successfully.")
        return hashed
    except Exception as e:
        logging.error(f"Password hashing error: {e}")
        print("[!] Failed to hash password.")

def check_password(password: str, hashed: bytes) -> bool:
    try:
        result = bcrypt.checkpw(password.encode(), hashed)
        logging.info(f"Password check: {'Success' if result else 'Failure'}")
        return result
    except Exception as e:
        logging.error(f"Password verification error: {e}")
        print("[!] Failed to verify password.")
        return False

# ====== File Encryption/Decryption ====== #
def encrypt_file(file_path: str):
    try:
        if not os.path.exists(file_path):
            print(f"[!] File not found: {file_path}")
            return
        # Avoid double .enc extension
        if file_path.endswith(".enc"):
            print("[!] File already has .enc extension. Please provide original file.")
            return
        output_path = file_path + ".enc"
        if os.path.exists(output_path):
            overwrite = input(f"[?] Encrypted file {output_path} exists. Overwrite? (y/n): ").strip().lower()
            if overwrite != 'y':
                print("[*] Encryption cancelled.")
                return
        with open(file_path, 'rb') as file:
            data = file.read()
        encrypted = fernet.encrypt(data)
        with open(output_path, 'wb') as file:
            file.write(encrypted)
        logging.info(f"Encrypted file: {file_path}")
        print(f"[+] File encrypted: {output_path}")
    except Exception as e:
        logging.error(f"Error encrypting file {file_path}: {e}")
        print("[!] Error during encryption.")

def decrypt_file(file_path: str):
    try:
        if not os.path.exists(file_path):
            print(f"[!] File not found: {file_path}")
            return
        with open(file_path, 'rb') as file:
            data = file.read()
        try:
            decrypted = fernet.decrypt(data)
        except Exception as e:
            logging.error(f"Decryption failed for file {file_path}: {e}")
            print("[!] Decryption failed. File may be corrupted or not encrypted with this key.")
            return
        if file_path.endswith(".enc"):
            output_path = file_path[:-4] + ".dec"
        else:
            output_path = file_path + ".dec"
        if os.path.exists(output_path):
            overwrite = input(f"[?] Decrypted file {output_path} exists. Overwrite? (y/n): ").strip().lower()
            if overwrite != 'y':
                print("[*] Decryption cancelled.")
                return
        with open(output_path, 'wb') as file:
            file.write(decrypted)
        logging.info(f"Decrypted file: {file_path}")
        print(f"[+] File decrypted: {output_path}")
    except Exception as e:
        logging.error(f"Error decrypting file {file_path}: {e}")
        print("[!] Error during decryption.")

# ====== Image & Video Handlers ====== #
def encrypt_image(image_path: str): encrypt_file(image_path)
def decrypt_image(encrypted_path: str): decrypt_file(encrypted_path)
def encrypt_video(video_path: str): encrypt_file(video_path)
def decrypt_video(encrypted_path: str): decrypt_file(encrypted_path)

# ====== View Log File ====== #
def view_log():
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
        if not os.path.exists(LOG_FILE):
            print("[!] No log file found.")
            return
        with open(LOG_FILE, "r") as log:
            print("\n--- Log File Contents ---")
            for line in log:
                print(line.strip())
            print("--- End of Log ---")
    except Exception as e:
        logging.error(f"Error viewing log: {e}")
        print("[!] Could not open log file.")

# ====== User Interface Menu ====== #
def menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(BANNER)
        print("--- Main Menu ---")
        print("1. Hash Password")
        print("2. Encrypt File")
        print("3. Decrypt File")
        print("4. Encrypt Image")
        print("5. Decrypt Image")
        print("6. Encrypt Video")
        print("7. Decrypt Video")
        print("8. Exit")
        print("9. View Log File")
        print("10. Check Password")
        try:
            choice = input("Enter your choice: ").strip()

            if choice == '1':
                pw = input("Enter password to hash: ")
                hashed = hash_password(pw)
                if hashed:
                    try:
                        print(f"[+] Hashed password: {hashed.decode()}")
                    except Exception as e:
                        print("[!] Error displaying hashed password.")
                        logging.error(f"Error decoding hashed password: {e}")
            elif choice == '2':
                path = input("Enter path to file: ")
                encrypt_file(path)
            elif choice == '3':
                path = input("Enter path to encrypted file (.enc): ")
                decrypt_file(path)
            elif choice == '4':
                path = input("Enter path to image: ")
                encrypt_image(path)
            elif choice == '5':
                path = input("Enter path to encrypted image: ")
                decrypt_image(path)
            elif choice == '6':
                path = input("Enter path to video: ")
                encrypt_video(path)
            elif choice == '7':
                path = input("Enter path to encrypted video: ")
                decrypt_video(path)
            elif choice == '8':
                logging.info("User exited the program.")
                print("Exiting...")
                break
            elif choice == '9':
                view_log()
            elif choice == '10':
                pw = input("Enter password to verify: ")
                hashed_input = input("Enter hashed password: ").strip()
                try:
                    hashed = hashed_input.encode()
                except Exception as e:
                    print("[!] Invalid hashed password input.")
                    logging.error(f"Invalid hashed password input: {e}")
                    continue
                if check_password(pw, hashed):
                    print("[+] Password match.")
                else:
                    print("[!] Password does not match.")
            else:
                print("Invalid choice. Try again.")
                logging.warning("Invalid menu choice entered.")
        except KeyboardInterrupt:
            print("\n[!] Interrupted. Exiting.")
            break
        except Exception as e:
            logging.error(f"Menu error: {e}")
            print("[!] An error occurred. Try again.")

        input("\nPress Enter to return to menu...")

if __name__ == "__main__":
    menu()
