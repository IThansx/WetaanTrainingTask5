
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import keywrap
from cryptography.exceptions import InvalidKey, InvalidSignature
from getpass import getpass
import base64
import os

def utf8(s: bytes):
    return str(s, 'utf-8')

# Password-based key derivation function to derive a key from a password
def derive_key(password: str, salt: bytes, length: int = 32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Save the private key securely by encrypting it with a password
def save_private_key(private_key, filename, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    encrypted_private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(key)
    )
    with open(filename, 'wb') as f:
        f.write(salt + encrypted_private_pem)
    print(f"Private key saved to '{filename}' securely")

# Load the private key securely by decrypting it with a password
def load_private_key(filename, password):
    with open(filename, 'rb') as f:
        data = f.read()
    salt = data[:16]
    encrypted_private_pem = data[16:]
    key = derive_key(password, salt)
    private_key = serialization.load_pem_private_key(
        encrypted_private_pem,
        password=key,
        backend=default_backend()
    )
    return private_key

# Generate RSA keys and save them 
def generate_and_save_keys(password):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Save the private key securely
    save_private_key(private_key, 'private_key.pem', password)

    # Save the public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('public_key.pem', 'wb') as f:
        f.write(public_pem)
    print("Public key saved to 'public_key.pem'")

# Encrypt and save data securely
def encrypt_and_save_data(aes_key, iv, plaintext):
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Encrypt the AES key with the RSA public key
    with open('public_key.pem', 'rb') as f:
        public_pem = f.read()
    public_key = serialization.load_pem_public_key(public_pem, backend=default_backend())
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save encrypted data, encrypted AES key, and IV to files
    with open('encrypted_data.bin', 'wb') as f:
        f.write(encrypted_data)
    with open('encrypted_aes_key.bin', 'wb') as f:
        f.write(encrypted_aes_key)
    with open('iv.bin', 'wb') as f:
        f.write(iv)

    print("Encrypted data saved to 'encrypted_data.bin'")
    print("Encrypted AES key saved to 'encrypted_aes_key.bin'")
    print("Initialization vector (IV) saved to 'iv.bin'")

# Basic key rotation mechanism
def rotate_keys(password):
    print("Rotating keys...")
    generate_and_save_keys(password)
    print("Keys rotated successfully")

# Access control: request password from the user
password = getpass("Enter password to secure your keys: ")

# Generate and save RSA keys
generate_and_save_keys(password)

# Generate a random AES key and IV
aes_key = os.urandom(32)  # AES-256 key
iv = os.urandom(16)  # Initialization vector for CBC mode

# Encrypt the plaintext using AES in CBC mode
plaintext = b'Hanin is the best'
encrypt_and_save_data(aes_key, iv, plaintext)

# Decryption process
try:
    # Load the private key securely
    password = getpass("Enter password to access your private key: ")
    private_key = load_private_key('private_key.pem', password)

    # Load the encrypted data, encrypted AES key, and IV from files
    with open('encrypted_data.bin', 'rb') as f:
        encrypted_data = f.read()
    with open('encrypted_aes_key.bin', 'rb') as f:
        encrypted_aes_key = f.read()
    with open('iv.bin', 'rb') as f:
        iv = f.read()

    #decrypt the AES key with the RSA private key
    decrypted_aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    #decrypt data using AES in CBC mode
    cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    #remove padding
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    # Verify that the decrypted data matches the original plaintext
    assert decrypted_data == plaintext, " decrypted data does not match the original plaintext"

    print(f'plaintext: \033[1;33m{utf8(plaintext)}\033[0m')
    print(f'encrypted: \033[1;32m{base64.b64encode(encrypted_data).decode()}\033[0m')
    print(f'decrypted: \033[1;31m{utf8(decrypted_data)}\033[0m')

except (InvalidKey, InvalidSignature) as e:
    print(f"Error during decryption: {e}")
except AssertionError as e:
    print(f"Verification failed: {e}")
except Exception as e:
    print(f"An error happened: {e}")

# Trigger key rotation 
rotate_keys(password)