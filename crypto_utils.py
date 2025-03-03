from Crypto.Cipher import AES
import base64
import os

# AES key size: 16, 24, or 32 bytes
KEY = b"thisisasecretkey12345678901234"  # Change this in production

def pad(data):
    """Pad data to be a multiple of 16 bytes (AES block size)."""
    return data + (16 - len(data) % 16) * chr(16 - len(data) % 16)

def unpad(data):
    """Remove padding after decryption."""
    return data[:-ord(data[-1])]

def encrypt_message(message):
    """Encrypt a message using AES encryption."""
    cipher = AES.new(KEY, AES.MODE_CBC, iv=KEY[:16])
    encrypted = cipher.encrypt(pad(message).encode())
    return base64.b64encode(encrypted).decode()

def decrypt_message(encrypted_message):
    """Decrypt an AES-encrypted message."""
    cipher = AES.new(KEY, AES.MODE_CBC, iv=KEY[:16])
    decrypted = cipher.decrypt(base64.b64decode(encrypted_message))
    return unpad(decrypted.decode())
