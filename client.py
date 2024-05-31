import socket
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

p = 23
g = 5

def generate_private_key():
    return random.randint(1, p-1)

def calculate_public_key(private_key):
    return pow(g, private_key, p)

def calculate_shared_secret(public_key, private_key):
    return pow(public_key, private_key, p)

def encrypt_message(message, key):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    iv = b'\x00' * 16  # Инициализационный вектор (может быть случайным)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(padded_data) + encryptor.finalize()

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 65432))

private_key = generate_private_key()
public_key = calculate_public_key(private_key)

client_socket.sendall(str(public_key).encode())

server_public_key = int(client_socket.recv(1024).decode())
print(f"Received server public key: {server_public_key}")

shared_secret = calculate_shared_secret(server_public_key, private_key)
print(f"Shared secret: {shared_secret}")

message = "Hello, Secure World!"
encrypted_message = encrypt_message(message, shared_secret.to_bytes(16, 'big'))
client_socket.sendall(encrypted_message)

client_socket.close()