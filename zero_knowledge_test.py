import os
import json
import base64
from argon2 import low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class VaultManager:
    """Handles professional JSON storage with Atomic Writes."""
    def __init__(self, filename="vault.json"):
        self.filename = filename

    def save(self, service, ciphertext, salt, nonce):
        if os.path.exists(self.filename):
            with open(self.filename, 'r') as f:
                data = json.load(f)
        else:
            data = {"secrets": []}

        entry = {
            "service": service,
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "salt": base64.b64encode(salt).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8')
        }
        data["secrets"].append(entry)

        temp_file = self.filename + ".tmp"
        with open(temp_file, 'w') as f:
            json.dump(data, f, indent=4)
        os.replace(temp_file, self.filename)

    def load_and_decrypt(self, service_name, master_password):
        if not os.path.exists(self.filename):
            return "❌ Vault file not found."

        with open(self.filename, 'r') as f:
            data = json.load(f)

        for entry in data["secrets"]:
            if entry["service"] == service_name:
                ciphertext = base64.b64decode(entry["ciphertext"])
                salt = base64.b64decode(entry["salt"])
                nonce = base64.b64decode(entry["nonce"])

                try:
                    # Calling the helper function below
                    decrypted_text = decrypt_vault(master_password, salt, nonce, ciphertext)
                    return decrypted_text
                except Exception:
                    return "❌ Decryption Failed (Wrong Password or Tampered Data)"

        return " Service not found in vault."

# --- CRYPTO LOGIC ---

def derive_key(password, salt):
    return low_level.hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=low_level.Type.ID
    )

def encrypt_entry(password, plaintext):
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return salt, nonce, ciphertext

def decrypt_vault(password, salt, nonce, ciphertext):
    """Reconstructs the key and unlocks the data."""
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted_bytes.decode()

# --- TESTING THE COMPLETE LOOP ---

if __name__ == "__main__":
    master_password = "my-secret-password-123"
    service_name = "Google_Internship_Portal"
    secret_to_hide = "Candidate_ID: 9.5_CGPA_Merit"

    manager = VaultManager()

    print("---  Step 1: Encrypting & Saving ---")
    s, n, encrypted = encrypt_entry(master_password, secret_to_hide)
    manager.save(service_name, encrypted, s, n)
    print(f"✅ Success! Entry for '{service_name}' saved to vault.json\n")

    print("---  Step 2: Retrieving & Decrypting ---")
    result = manager.load_and_decrypt(service_name, master_password)
    print(f"Decrypted Content: {result}")