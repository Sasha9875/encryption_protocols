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