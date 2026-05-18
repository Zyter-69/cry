"""
TP 6 - Exercice 6.1: Secure Communication via TCP/IP Sockets
Demonstrates encrypted communication between client and server using RSA + AES
"""

import socket
import threading
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json


class SecureTCPServer:
    """Secure TCP Server using RSA + AES encryption"""
    
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.server_socket = None
        self.private_key = None
        self.public_key = None
        self.generate_keys()
    
    def generate_keys(self):
        """Generate RSA key pair (2048-bit)"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        print("[SERVER] RSA keys generated (2048-bit)")
    
    def start(self):
        """Start the secure TCP server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"[SERVER] Listening on {self.host}:{self.port}")
        
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                print(f"[SERVER] Client connected from {client_address}")
                
                # Handle client in a separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down...")
            self.server_socket.close()
    
    def handle_client(self, client_socket, client_address):
        """Handle communication with a single client"""
        try:
            # Send public key to client
            public_key_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            client_socket.send(public_key_pem)
            print(f"[SERVER] Public key sent to {client_address}")
            
            # Receive encrypted AES key from client
            encrypted_aes_key = client_socket.recv(256)
            aes_key = self.private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"[SERVER] AES key received from {client_address} (256-bit)")
            
            # Receive and decrypt messages
            while True:
                encrypted_data = client_socket.recv(1024)
                if not encrypted_data:
                    break
                
                # Decrypt using AES
                iv = encrypted_data[:16]
                ciphertext = encrypted_data[16:]
                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                
                # Remove padding
                plaintext = plaintext.rstrip(b'\x00')
                message = plaintext.decode('utf-8')
                
                print(f"[SERVER] {client_address}: {message}")
                
                # Send acknowledgment
                ack = "ACK: Message received"
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                
                # Add padding
                padded = (ack.encode('utf-8') + b'\x00' * 16)[:16 * ((len(ack) + 15) // 16)]
                ciphertext = encryptor.update(padded) + encryptor.finalize()
                client_socket.send(iv + ciphertext)
        
        except Exception as e:
            print(f"[SERVER] Error handling {client_address}: {e}")
        finally:
            client_socket.close()
            print(f"[SERVER] Client {client_address} disconnected")


class SecureTCPClient:
    """Secure TCP Client using RSA + AES encryption"""
    
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.socket = None
        self.server_public_key = None
        self.aes_key = None
    
    def connect(self):
        """Connect to secure TCP server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        print(f"[CLIENT] Connected to {self.host}:{self.port}")
        
        # Receive server's public key
        public_key_pem = self.socket.recv(2048)
        self.server_public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
        print("[CLIENT] Received server's public key (2048-bit RSA)")
        
        # Generate and send AES key
        self.aes_key = os.urandom(32)  # 256-bit AES key
        encrypted_aes_key = self.server_public_key.encrypt(
            self.aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.socket.send(encrypted_aes_key)
        print("[CLIENT] AES key sent (encrypted with RSA)")
    
    def send_message(self, message):
        """Send encrypted message to server"""
        try:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Add padding
            padded = (message.encode('utf-8') + b'\x00' * 16)[:16 * ((len(message) + 15) // 16)]
            ciphertext = encryptor.update(padded) + encryptor.finalize()
            
            self.socket.send(iv + ciphertext)
            
            # Receive acknowledgment
            encrypted_ack = self.socket.recv(1024)
            iv = encrypted_ack[:16]
            ciphertext = encrypted_ack[16:]
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext = plaintext.rstrip(b'\x00')
            
            print(f"[CLIENT] {plaintext.decode('utf-8')}")
        
        except Exception as e:
            print(f"[CLIENT] Error: {e}")
    
    def interactive_mode(self):
        """Interactive message sending"""
        print("[CLIENT] Type 'quit' to disconnect")
        while True:
            message = input("[CLIENT] Message: ").strip()
            if message.lower() == 'quit':
                break
            if message:
                self.send_message(message)
        self.socket.close()


def main():
    """Main menu for TCP Secure Communication"""
    print("=" * 70)
    print(" TP 6 - Exercice 6.1: Secure TCP/IP Socket Communication")
    print("=" * 70)
    print("\n1. Start Server")
    print("2. Start Client")
    print("3. Exit")
    
    choice = input("\nChoose [1-3]: ").strip()
    
    if choice == '1':
        server = SecureTCPServer(port=5000)
        server.start()
    
    elif choice == '2':
        client = SecureTCPClient(host='localhost', port=5000)
        try:
            client.connect()
            client.interactive_mode()
        except Exception as e:
            print(f"Connection error: {e}")
    
    elif choice == '3':
        return
    
    else:
        print("Invalid choice")


if __name__ == "__main__":
    main()
