import os
import json
import base64
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


DATA_FILE = "vault.json"
SALT_FILE = "vault.salt"
ITERATIONS = 600_000  

def get_or_create_salt() -> bytes:
    """Retrieves the existing salt or generates a new 16-byte cryptographic salt."""
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            return f.read()
    else:
        
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        return salt

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derives a secure 32-byte key from the master password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    
    derived = kdf.derive(master_password.encode())
    return base64.urlsafe_b64encode(derived)

def load_vault() -> dict:
    """Loads the raw encrypted vault data from disk."""
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_vault(data: dict):
    """Saves the encrypted vault data back to disk."""
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def add_credential(fernet: Fernet, service: str, username: str, secret: str):
    """Encrypts and stores a new credential entry."""
    vault = load_vault()
    
    
        encrypted_user = fernet.encrypt(username.encode()).decode()
    encrypted_secret = fernet.encrypt(secret.encode()).decode()
    
    vault[service.lower()] = {
        "username": encrypted_user,
        "secret": encrypted_secret
    }
    save_vault(vault)
    print(f"✅ Credential for '{service}' saved successfully.")

def get_credential(fernet: Fernet, service: str):
    """Retrieves and decrypts a specific credential."""
    vault = load_vault()
    service_key = service.lower()
    
    if service_key not in vault:
        print(f"❌ No credentials found for '{service}'.")
        return

    try:
    
        enc_data = vault[service_key]
        username = fernet.decrypt(enc_data["username"].encode()).decode()
        secret = fernet.decrypt(enc_data["secret"].encode()).decode()
        
        print(f"\n🔑 [ {service} ]")
        print(f"👤 Username: {username}")
        print(f"🔒 Password: {secret}")
    except Exception:
        print("❌ Decryption failed. The master password or vault file may be corrupted.")

def main():
    print("--- Secure Local Credential Manager ---")
    
    master_password = getpass("Enter Master Password: ")
    if not master_password:
        print("Master password cannot be empty.")
        return

    
    salt = get_or_create_salt()
    key = derive_key(master_password, salt)
    fernet = Fernet(key)

    while True:
        print("\nOptions: [1] Add Credential  [2] Retrieve Credential  [3] Exit")
        choice = input("Select an option: ").strip()

        if choice == "1":
            service = input("Enter Service/Website Name: ").strip()
            username = input("Enter Username/Email: ").strip()
            secret = getpass("Enter Password/Secret: ").strip()
            if service and username and secret:
                add_credential(fernet, service, username, secret)
            else:
                print("❌ All fields are required.")

        elif choice == "2":
            service = input("Enter Service Name to Retrieve: ").strip()
            if service:
    
                get_credential(fernet, service)

        elif choice == "3":
            print("🔒 Vault closed. Goodbye!")
            break
        else:
            print("Invalid choice. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()
