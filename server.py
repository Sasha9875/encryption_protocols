import socket
import random
import os
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

def save_key_to_file(key, filename):
    with open(filename, 'w') as file:
        file.write(str(key))

def load_key_from_file(filename):
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            return int(file.read())
    return None

def encrypt_message(message, key):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    iv = b'\x00' * 16  # Инициализационный вектор (может быть случайным)
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(padded_data) + encryptor.finalize()
def decrypt_message(encrypted_message, key):
    iv = encrypted_message[:16]
    encrypted_message = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65432))
server_socket.listen(1)

print("Server is listening on port 65432")

private_key = load_key_from_file('server_private_key.txt')
if private_key is None:
    private_key = generate_private_key()
    save_key_to_file(private_key, 'server_private_key.txt')

public_key = load_key_from_file('server_public_key.txt')
if public_key is None:
    public_key = calculate_public_key(private_key)
    save_key_to_file(public_key, 'server_public_key.txt')

conn, addr = server_socket.accept()
print(f"Connected by {addr}")

private_key = generate_private_key()
public_key = calculate_public_key(private_key)

client_public_key = int(conn.recv(1024).decode())
print(f"Received client public key: {client_public_key}")

conn.sendall(str(public_key).encode())
shared_secret = calculate_shared_secret(client_public_key, private_key)
print(f"Shared secret: {shared_secret}")
encrypted_message = conn.recv(1024)
print(f"Encrypted message received: {encrypted_message}")
decrypted_message = decrypt_message(encrypted_message, shared_secret.to_bytes(16, 'big'))
print(f"Decrypted message: {decrypted_message.decode()}")
conn.close()