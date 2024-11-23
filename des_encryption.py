# des_encryption.py
import base64
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib

def generate_3des_key(seed):
   
    key_bytes = hashlib.sha256(str(seed).encode()).digest()[:24]
    return key_bytes

def encrypt_3des(message, key):
   
    
    key_bytes = generate_3des_key(key)
    
    
    message_bytes = str(message).encode('utf-8')
    
    
    cipher = DES3.new(key_bytes, DES3.MODE_ECB)
    
    
    padded_message = pad(message_bytes, DES3.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    
    return base64.b64encode(encrypted_message).decode('utf-8')

def decrypt_3des(encrypted_message, key):
    
    
    key_bytes = generate_3des_key(key)
    
   
    encrypted_bytes = base64.b64decode(encrypted_message)
    
    
    cipher = DES3.new(key_bytes, DES3.MODE_ECB)
    
   
    decrypted_padded = cipher.decrypt(encrypted_bytes)
    decrypted_message = unpad(decrypted_padded, DES3.block_size)
    
    
    return int(decrypted_message.decode('utf-8'))