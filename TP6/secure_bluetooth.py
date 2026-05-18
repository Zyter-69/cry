"""
TP 6 - Exercice 6.2: Secure Bluetooth Communication (RFCOMM)
Demonstrates encrypted communication over Bluetooth using RFCOMM protocol
Note: Requires pybluez library - install with: pip install pybluez
"""

import os
import threading
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Try to import pybluez for Bluetooth support
try:
    import bluetooth
    BLUETOOTH_AVAILABLE = True
except ImportError:
    BLUETOOTH_AVAILABLE = False
    print("[WARNING] pybluez not installed. Install with: pip install pybluez")


class SecureBluetoothServer:
    """Secure Bluetooth Server using RFCOMM + RSA + AES encryption"""
    
    def __init__(self, service_name="SecureChat", port=1):
        self.service_name = service_name
        self.port = port
        self.server_socket = None
        self.private_key = None
        self.public_key = None
        self.uuid = "94f39d29-7d6d-437d-973b-fba39e49d4ee"  # Random UUID for service
        self.generate_keys()
    
    def generate_keys(self):
        """Generate RSA key pair (2048-bit)"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        print("[BT-SERVER] RSA keys generated (2048-bit)")
    
    def start(self):
        """Start Bluetooth RFCOMM server"""
        if not BLUETOOTH_AVAILABLE:
            print("[BT-SERVER] Error: pybluez not installed")
            print("[BT-SERVER] Install with: pip install pybluez")
            return
        
        try:
            self.server_socket = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            self.server_socket.bind(("", bluetooth.PORT_ANY))
            self.server_socket.listen(1)
            
            port = self.server_socket.getsockname()[1]
            print(f"[BT-SERVER] RFCOMM listening on port {port}")
            
            # Advertise service
            bluetooth.advertise_service(
                self.server_socket,
                self.service_name,
                service_id=self.uuid,
                service_classes=[self.uuid],
                profiles=[bluetooth.SERIAL_PORT_PROFILE]
            )
            print(f"[BT-SERVER] Service '{self.service_name}' advertised")
            
            # Accept connections
            while True:
                try:
                    client_socket, client_info = self.server_socket.accept()
                    print(f"[BT-SERVER] Client connected: {client_info}")
                    
                    # Handle client in thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_info)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                
                except KeyboardInterrupt:
                    break
        
        except Exception as e:
            print(f"[BT-SERVER] Error: {e}")
            print("[BT-SERVER] Note: Bluetooth may not be available on this system")
            print("[BT-SERVER] For testing, use the simulator mode below")
        
        finally:
            if self.server_socket:
                self.server_socket.close()
    
    def handle_client(self, client_socket, client_info):
        """Handle communication with a single Bluetooth client"""
        try:
            # Send public key to client
            public_key_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            client_socket.send(public_key_pem)
            print(f"[BT-SERVER] Public key sent to {client_info}")
            
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
            print(f"[BT-SERVER] AES key received from {client_info} (256-bit)")
            
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
                
                print(f"[BT-SERVER] {client_info}: {message}")
                
                # Send acknowledgment
                ack = "ACK: Message received"
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                
                padded = (ack.encode('utf-8') + b'\x00' * 16)[:16 * ((len(ack) + 15) // 16)]
                ciphertext = encryptor.update(padded) + encryptor.finalize()
                client_socket.send(iv + ciphertext)
        
        except Exception as e:
            print(f"[BT-SERVER] Error: {e}")
        
        finally:
            client_socket.close()
            print(f"[BT-SERVER] Client {client_info} disconnected")


class SecureBluetoothClient:
    """Secure Bluetooth Client using RFCOMM + RSA + AES encryption"""
    
    def __init__(self, service_name="SecureChat"):
        self.service_name = service_name
        self.socket = None
        self.server_public_key = None
        self.aes_key = None
    
    def discover_services(self):
        """Discover available Bluetooth services"""
        if not BLUETOOTH_AVAILABLE:
            print("[BT-CLIENT] Error: pybluez not installed")
            return []
        
        print("[BT-CLIENT] Scanning for Bluetooth devices...")
        nearby_devices = bluetooth.discover_devices()
        
        services = []
        for bdaddr in nearby_devices:
            print(f"[BT-CLIENT] Searching for services on {bdaddr}")
            try:
                service_matches = bluetooth.find_service(address=bdaddr, uuid=None)
                services.extend(service_matches)
            except Exception as e:
                print(f"[BT-CLIENT] Error scanning {bdaddr}: {e}")
        
        return services
    
    def connect(self, server_address):
        """Connect to Bluetooth server"""
        if not BLUETOOTH_AVAILABLE:
            print("[BT-CLIENT] Error: pybluez not installed")
            return False
        
        try:
            self.socket = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            self.socket.connect((server_address, 1))
            print(f"[BT-CLIENT] Connected to {server_address}")
            
            # Receive server's public key
            public_key_pem = self.socket.recv(2048)
            self.server_public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            print("[BT-CLIENT] Received server's public key (2048-bit RSA)")
            
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
            print("[BT-CLIENT] AES key sent (encrypted with RSA)")
            
            return True
        
        except Exception as e:
            print(f"[BT-CLIENT] Connection error: {e}")
            return False
    
    def send_message(self, message):
        """Send encrypted message to Bluetooth server"""
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
            
            print(f"[BT-CLIENT] {plaintext.decode('utf-8')}")
        
        except Exception as e:
            print(f"[BT-CLIENT] Error: {e}")
    
    def interactive_mode(self):
        """Interactive message sending"""
        print("[BT-CLIENT] Type 'quit' to disconnect")
        while True:
            message = input("[BT-CLIENT] Message: ").strip()
            if message.lower() == 'quit':
                break
            if message:
                self.send_message(message)
        self.socket.close()


class BluetoothSimulator:
    """Simulator for Bluetooth testing (when hardware not available)"""
    
    def __init__(self):
        self.server = None
        self.client = None
    
    def run_simulation(self):
        """Run simulated Bluetooth communication"""
        print("=" * 70)
        print(" BLUETOOTH COMMUNICATION SIMULATION (pybluez not available)")
        print("=" * 70)
        print("\n[SIMULATION] This demonstrates the encryption flow without")
        print("[SIMULATION] actual Bluetooth hardware.")
        print("\n[SIMULATION] Flow:")
        print("  1. Server generates RSA-2048 keys")
        print("  2. Client requests connection")
        print("  3. Server sends public key to client")
        print("  4. Client generates AES-256 key")
        print("  5. Client encrypts AES key with server's RSA key")
        print("  6. Server decrypts AES key with private key")
        print("  7. All messages encrypted with AES-256-CBC")
        
        # Simulate server
        print("\n[SIMULATION] --- Server Setup ---")
        server = SecureBluetoothServer(service_name="SimulatedChat")
        
        print("\n[SIMULATION] --- Client Setup ---")
        client = SecureBluetoothClient()
        
        # Simulate key exchange
        print("\n[SIMULATION] --- Key Exchange ---")
        server_pub_pem = server.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client.server_public_key = serialization.load_pem_public_key(
            server_pub_pem,
            backend=default_backend()
        )
        print("[SIMULATION] ✓ Server's public key transferred to client")
        
        # Client generates and encrypts AES key
        client.aes_key = os.urandom(32)
        encrypted_aes = client.server_public_key.encrypt(
            client.aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("[SIMULATION] ✓ Client's AES-256 key encrypted with RSA")
        
        # Server decrypts AES key
        decrypted_aes = server.private_key.decrypt(
            encrypted_aes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("[SIMULATION] ✓ Server decrypted AES key")
        
        # Test encrypted message transmission
        print("\n[SIMULATION] --- Encrypted Message Exchange ---")
        test_message = "Hello from Bluetooth Client!"
        
        # Client encrypts
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(client.aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded = (test_message.encode('utf-8') + b'\x00' * 16)[:16 * ((len(test_message) + 15) // 16)]
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        encrypted_packet = iv + ciphertext
        
        print(f"[SIMULATION] Message: {test_message}")
        print(f"[SIMULATION] Encrypted: {encrypted_packet.hex()[:64]}... (truncated)")
        
        # Server decrypts
        iv_received = encrypted_packet[:16]
        ciphertext_received = encrypted_packet[16:]
        cipher = Cipher(algorithms.AES(decrypted_aes), modes.CBC(iv_received), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext_received) + decryptor.finalize()
        decrypted = decrypted.rstrip(b'\x00')
        
        print(f"[SIMULATION] Decrypted: {decrypted.decode('utf-8')}")
        print("\n[SIMULATION] ✓ Message successfully encrypted and decrypted!")


def main():
    """Main menu for Bluetooth Secure Communication"""
    print("=" * 70)
    print(" TP 6 - Exercice 6.2: Secure Bluetooth Communication (RFCOMM)")
    print("=" * 70)
    
    if not BLUETOOTH_AVAILABLE:
        print("\n[WARNING] pybluez not available on this system")
        print("[WARNING] Running simulation mode instead\n")
        
        simulator = BluetoothSimulator()
        simulator.run_simulation()
        return
    
    print("\n1. Start Bluetooth Server (RFCOMM)")
    print("2. Connect as Bluetooth Client")
    print("3. Discover Bluetooth Services")
    print("4. Exit")
    
    choice = input("\nChoose [1-4]: ").strip()
    
    if choice == '1':
        server = SecureBluetoothServer()
        server.start()
    
    elif choice == '2':
        client = SecureBluetoothClient()
        server_address = input("Enter server Bluetooth address (MAC format): ").strip()
        
        if client.connect(server_address):
            client.interactive_mode()
        else:
            print("Failed to connect")
    
    elif choice == '3':
        client = SecureBluetoothClient()
        services = client.discover_services()
        
        if services:
            print("\nFound services:")
            for i, service in enumerate(services, 1):
                print(f"  {i}. {service.get('name', 'Unknown')}")
                print(f"     Address: {service.get('host', 'Unknown')}")
                print(f"     Port: {service.get('port', 'Unknown')}")
        else:
            print("No services found")
    
    elif choice == '4':
        return
    
    else:
        print("Invalid choice")


if __name__ == "__main__":
    main()
