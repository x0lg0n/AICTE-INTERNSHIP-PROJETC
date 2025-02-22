import cv2
import numpy as np
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

# Constants
HEADER_SIZE = 32  # Bits for storing message length
SALT_SIZE = 16
IV_SIZE = 16

def derive_key(password: str, salt: bytes, iterations=100000) -> bytes:
    """Derive AES key using PBKDF2-HMAC-SHA256"""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=32)

def encrypt_message(message: str, password: str) -> str:
    """Encrypt message with AES-256-CBC using proper key derivation"""
    salt = get_random_bytes(SALT_SIZE)
    iv = get_random_bytes(IV_SIZE)
    key = derive_key(password, salt)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    
    # Combine salt + iv + ciphertext
    encrypted_data = salt + iv + encrypted
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_message(encrypted_data: str, password: str) -> str:
    """Decrypt AES-256-CBC encrypted message"""
    encrypted_data = base64.b64decode(encrypted_data)
    salt = encrypted_data[:SALT_SIZE]
    iv = encrypted_data[SALT_SIZE:SALT_SIZE+IV_SIZE]
    ciphertext = encrypted_data[SALT_SIZE+IV_SIZE:]
    
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    try:
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted.decode('utf-8')
    except (ValueError, KeyError) as e:
        raise ValueError("Decryption failed: Invalid password or corrupted data") from e

def lsb_embed(image: np.ndarray, secret_data: str) -> np.ndarray:
    """Embed data in LSB plane with length header"""
    # Convert data to binary
    binary_data = ''.join(f"{ord(c):08b}" for c in secret_data)
    data_len = len(binary_data)
    
    # Add 32-bit header with data length
    header = f"{data_len:032b}"
    full_data = header + binary_data
    
    # Validate capacity
    if len(full_data) > image.size:
        raise ValueError(f"Message too large for image (needs {len(full_data)} bits, has {image.size})")
    
    # Flatten image and embed data
    flat_img = image.reshape(-1)
    for i, bit in enumerate(full_data):
        flat_img[i] = (flat_img[i] & 0xFE) | int(bit)
    
    return flat_img.reshape(image.shape)

def lsb_extract(image: np.ndarray) -> str:
    """Extract data from LSB plane with length header"""
    flat_img = image.reshape(-1)
    
    # Extract header (first 32 bits)
    header = ''.join(str(flat_img[i] & 1) for i in range(HEADER_SIZE))
    data_len = int(header, 2)
    
    # Validate extracted length
    if data_len <= 0 or data_len > (len(flat_img) - HEADER_SIZE):
        raise ValueError("Invalid message length detected")
    
    # Extract message data
    binary_data = ''.join(str(flat_img[i] & 1) for i in range(HEADER_SIZE, HEADER_SIZE + data_len))
    
    # Convert to string
    chars = []
    for i in range(0, data_len, 8):
        byte = binary_data[i:i+8]
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)