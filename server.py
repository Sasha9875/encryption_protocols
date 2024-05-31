import socket
import random
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class DiffieHellman:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.private_key = self.load_key_from_file('server_private_key.txt') or self.generate_private_key()
        self.public_key = self.load_key_from_file('server_public_key.txt') or self.calculate_public_key()
        self.save_key_to_file(self.private_key, 'server_private_key.txt')
        self.save_key_to_file(self.public_key, 'server_public_key.txt')

    def generate_private_key(self):
        return random.randint(1, self.p-1)

    def calculate_public_key(self):
        return pow(self.g, self.private_key, self.p)

    def calculate_shared_secret(self, public_key):
        return pow(public_key, self.private_key, self.p)

    @staticmethod
    def save_key_to_file(key, filename):
        with open(filename, 'w') as file:
            file.write(str(key))

    @staticmethod
    def load_key_from_file(filename):
        if os.path.exists(filename):
            with open(filename, 'r') as file:
                return int(file.read())
        return None

class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, message):
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        iv = b'\x00' * 16
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return iv + encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, encrypted_message):
        iv = encrypted_message[:16]
        encrypted_message = encrypted_message[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_message) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

def main():
    p = 23
    g = 5
    dh = DiffieHellman(p, g)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65432))
    server_socket.listen(1)

    print("Server is listening on port 65432")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    client_public_key = int(conn.recv(1024).decode())
    print(f"Received client public key: {client_public_key}")

    conn.sendall(str(dh.public_key).encode())

    shared_secret = dh.calculate_shared_secret(client_public_key)
    print(f"Shared secret: {shared_secret}")

    aes_cipher = AESCipher(shared_secret.to_bytes(16, 'big'))

    encrypted_message = conn.recv(1024)
    print(f"Encrypted message received: {encrypted_message}")

    decrypted_message = aes_cipher.decrypt(encrypted_message)
    print(f"Decrypted message: {decrypted_message.decode()}")

    conn.close()

if __name__ == "__main__":
    main()
