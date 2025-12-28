import os
from argon2 import low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- STEP 1: KEY DERIVATION ---
def derive_key(password, salt):
    """Turns a password into a 32-byte key using Argon2id."""
    return low_level.hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,          
        memory_cost=65536,    
        parallelism=4,        
        hash_len=32,          
        type=low_level.Type.ID
    )

# --- STEP 2: ENCRYPTION ---
def encrypt_vault(password, plaintext):
    """Encrypts data and returns the ingredients needed to unlock it later."""
    salt = os.urandom(16)        # Unique for every 'user'
    nonce = os.urandom(12)       # Unique for every encryption operation
    
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    
    # AES-GCM returns: Ciphertext + 16-byte Auth Tag
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    
    return salt, nonce, ciphertext

# --- STEP 3: DECRYPTION ---
def decrypt_vault(password, salt, nonce, ciphertext):
    """Reconstructs the key and unlocks the data."""
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    
    # This will throw an error if the password is wrong!
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted_bytes.decode()

# --- RUNNING THE TEST ---
if __name__ == "__main__":
    master_password = "my-secret-password-123"
    my_vault_data = "Gmail: pass1, Bank: pass2, Netflix: pass3"

    print("--- 1. Starting Encryption ---")
    s, n, encrypted = encrypt_vault(master_password, my_vault_data)
    
    print(f"Encrypted Data (Hex): {encrypted.hex()}")
    print(f"Salt (Hex): {s.hex()}")
    print(f"Nonce (Hex): {n.hex()}")
    print("-" * 30)
    #master_password = "my-secret-password-122"
   

    print("--- 2. Attempting Decryption ---")
    try:
        decrypted_output = decrypt_vault(master_password, s, n, encrypted)
        print(f"SUCCESS! Decrypted data: {decrypted_output}")
    except Exception as e:
        print("FAILED! Could not decrypt.")