"""
TP 6 - Exercice 6.3: Secure UDP Chat Application
Demonstrates encrypted chat communication using UDP sockets + AES encryption
"""

import socket
import threading
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import json


class SecureUDPChat:
    """Secure UDP Chat with AES-256-CBC encryption"""
    
    def __init__(self, username, shared_key, local_port=5001):
        self.username = username
        self.shared_key = hashlib.sha256(shared_key.encode()).digest()  # 256-bit key
        self.local_port = local_port
        self.socket = None
        self.peers = {}  # peer_address: last_seen
        self.running = False
    
    def start(self):
        """Start UDP socket"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('0.0.0.0', self.local_port))
        self.running = True
        print(f"[{self.username}] UDP Chat started on port {self.local_port}")
    
    def encrypt_message(self, plaintext):
        """Encrypt message using AES-256-CBC"""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.shared_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Add PKCS7 padding
        padding_length = 16 - (len(plaintext) % 16)
        padded = plaintext + bytes([padding_length] * padding_length)
        
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return iv + ciphertext
    
    def decrypt_message(self, encrypted_data):
        """Decrypt message using AES-256-CBC"""
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        cipher = Cipher(algorithms.AES(self.shared_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS7 padding
        padding_length = plaintext[-1]
        plaintext = plaintext[:-padding_length]
        
        return plaintext.decode('utf-8')
    
    def send_message(self, recipient_addr, message):
        """Send encrypted message to peer"""
        try:
            encrypted = self.encrypt_message(message.encode('utf-8'))
            self.socket.sendto(encrypted, recipient_addr)
            print(f"[{self.username}] → {recipient_addr}: {message}")
        except Exception as e:
            print(f"[{self.username}] Send error: {e}")
    
    def receive_messages(self):
        """Receive and decrypt messages from peers"""
        print(f"[{self.username}] Listening for messages...")
        while self.running:
            try:
                encrypted_data, sender_addr = self.socket.recvfrom(1024)
                self.peers[sender_addr] = True
                
                plaintext = self.decrypt_message(encrypted_data)
                print(f"\n[{self.username}] ← {sender_addr}: {plaintext}")
                print(f"[{self.username}] Enter message (or 'quit'): ", end='', flush=True)
            
            except Exception as e:
                print(f"[{self.username}] Receive error: {e}")
    
    def display_peers(self):
        """Display known peers"""
        if self.peers:
            print(f"\n[{self.username}] Known peers:")
            for i, peer in enumerate(self.peers.keys(), 1):
                print(f"  {i}. {peer}")
        else:
            print(f"\n[{self.username}] No known peers yet")
    
    def interactive_mode(self):
        """Interactive chat interface"""
        # Start receiving thread
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.daemon = True
        receive_thread.start()
        
        print(f"\n[{self.username}] Chat started. Commands:")
        print("  message → Send to all known peers")
        print("  send <peer_index> <message> → Send to specific peer")
        print("  peers → List known peers")
        print("  quit → Exit")
        
        while self.running:
            try:
                cmd = input(f"[{self.username}] Enter message (or 'quit'): ").strip()
                
                if cmd.lower() == 'quit':
                    self.running = False
                    break
                
                elif cmd.lower() == 'peers':
                    self.display_peers()
                
                elif cmd.lower().startswith('send '):
                    parts = cmd.split(maxsplit=2)
                    if len(parts) >= 3:
                        try:
                            peer_index = int(parts[1]) - 1
                            message = parts[2]
                            peers_list = list(self.peers.keys())
                            if 0 <= peer_index < len(peers_list):
                                peer_addr = peers_list[peer_index]
                                self.send_message(peer_addr, message)
                        except ValueError:
                            print("Invalid peer index")
                
                elif cmd:
                    # Send to all peers
                    for peer_addr in self.peers.keys():
                        self.send_message(peer_addr, cmd)
            
            except KeyboardInterrupt:
                self.running = False
                break
        
        self.socket.close()
        print(f"\n[{self.username}] Chat closed")


def main():
    """Main menu for Secure UDP Chat"""
    print("=" * 70)
    print(" TP 6 - Exercice 6.3: Secure UDP Chat Application")
    print("=" * 70)
    
    username = input("\nEnter your username: ").strip()
    shared_key = input("Enter shared encryption key: ").strip()
    port = input("Enter local port (default 5001): ").strip()
    
    port = int(port) if port else 5001
    
    chat = SecureUDPChat(username, shared_key, port)
    chat.start()
    chat.interactive_mode()


if __name__ == "__main__":
    main()
