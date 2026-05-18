# TP 6 - Secure Communications Application

## Overview
TP 6 demonstrates practical implementation of secure communication protocols and applications using cryptographic techniques learned in previous TPs.

## Exercises

### Exercice 6.1: Secure TCP/IP Socket Communication
**File**: `secure_tcp_sockets.py`

Implements encrypted client-server communication using:
- **RSA (2048-bit)**: For key exchange
- **AES-256-CBC**: For message encryption

**Features**:
- Server generates RSA key pair
- Server's public key sent to client
- Client generates random AES-256 key
- AES key encrypted with RSA and sent to server
- All messages encrypted with AES
- Thread-based multi-client support

**Usage**:
```bash
# Terminal 1 - Start Server
python secure_tcp_sockets.py
# Choose option 1

# Terminal 2 - Start Client
python secure_tcp_sockets.py
# Choose option 2
# Connect to localhost:5000
```

### Exercice 6.2: Secure Bluetooth Communication (RFCOMM)
**File**: `secure_bluetooth.py`

Implements encrypted Bluetooth communication using:
- **Bluetooth RFCOMM**: Radio Frequency Communication protocol
- **RSA (2048-bit)**: For key exchange over Bluetooth
- **AES-256-CBC**: For message encryption

**Features**:
- Server advertises Bluetooth service
- RFCOMM port negotiation
- Automatic simulator mode when pybluez unavailable
- Service discovery capability
- Thread-based multi-client support

**Installation** (optional):
```bash
pip install pybluez
```

**Usage** (Linux/macOS with Bluetooth):
```bash
# Terminal 1 - Start Bluetooth Server
python secure_bluetooth.py
# Choose option 1

# Terminal 2 - Start Bluetooth Client
python secure_bluetooth.py
# Choose option 2
# Enter server's MAC address

# Or discover services
python secure_bluetooth.py
# Choose option 3
```

**Simulator Mode** (when Bluetooth hardware unavailable):
```bash
python secure_bluetooth.py
# Automatically runs simulation demonstrating:
# - Server RSA key generation
# - Client-server key exchange
# - AES key encryption with RSA
# - Message encryption/decryption flow
```

### Exercice 6.3: Secure UDP Chat Application
**File**: `secure_udp_chat.py`

Implements peer-to-peer encrypted chat using:
- **UDP Sockets**: For datagram-based communication
- **AES-256-CBC**: For message encryption
- **Shared Key**: Pre-shared secret for symmetric encryption

**Features**:
- Multiple peers can connect on same or different machines
- All messages encrypted with shared AES key
- PKCS7 padding for block alignment
- Peer discovery and management
- Message broadcast or unicast

**Usage**:
```bash
# Terminal 1 - User Alice (port 5001)
python secure_udp_chat.py
# Username: Alice
# Shared key: mysecretkey123
# Port: 5001

# Terminal 2 - User Bob (port 5002)
python secure_udp_chat.py
# Username: Bob
# Shared key: mysecretkey123
# Port: 5002

# Now Bob can send to Alice:
# send 1 Hello Alice!
```

### Exercice 6.4: Secure Electronic Voting System
**File**: `secure_voting.py`

Demonstrates homomorphic encryption properties in voting context:
- **RSA (2048-bit)**: Additively homomorphic encryption
- **Encrypted Vote Tally**: Votes remain encrypted until final tally
- **Voter Authentication**: Registry prevents double voting

**Homomorphic Property**:
```
E(m1) * E(m2) ≡ E(m1 * m2) mod N
```

All encrypted votes can be multiplied together without decryption, then the result can be decrypted to get the final count.

**Features**:
- Anonymous voting (encrypted votes)
- Voter registry (prevent double voting)
- Encrypted audit trail
- Interactive voting interface
- Demo mode showing homomorphic properties

**Usage**:
```bash
python secure_voting.py

# Option 1: Interactive Voting
# - Cast votes as different voters
# - View voter registry
# - Tally encrypted votes
# - Export encrypted votes for audit

# Option 2: Demo Mode
# - Automatic demo with sample votes
# - Shows homomorphic encryption in action
```

## Security Concepts Demonstrated

### 1. RSA Key Exchange (TCP)
```
[Client] ← [Server's Public Key (RSA-2048)] ← [Server]
[Client] → [AES-256 key encrypted with RSA] → [Server]
[Client] ←→ [All messages encrypted with AES-256-CBC] ←→ [Server]
```

### 2. Bluetooth RFCOMM Key Exchange
```
[Bluetooth Client] ← [RFCOMM Channel] ← [Bluetooth Server]
[Client] ← [Server's Public Key (RSA-2048)] ← [Server]
[Client] → [AES-256 key encrypted with RSA] → [Server]
[Client] ←→ [Messages encrypted with AES-256-CBC] ←→ [Server]
```

### 3. Symmetric Encryption (UDP Chat)
```
Plaintext ─→ [AES-256-CBC] ─→ IV + Ciphertext ─→ Network
IV + Ciphertext ─→ [AES-256-CBC Decrypt] ─→ Plaintext
```

### 4. Homomorphic Encryption (Voting)
```
Vote₁ (Encrypted) × Vote₂ (Encrypted) = (Vote₁ × Vote₂) (Encrypted)
Result can only be decrypted by election authority
```

## Algorithm Specifications

| Protocol | Medium | Encryption | Key Exchange | Auth | Use Case |
|----------|--------|-----------|--------------|------|----------|
| TCP Socket | Ethernet | AES-256-CBC | RSA-2048 | ✓ | Server-Client (LAN/WAN) |
| Bluetooth | RFCOMM | AES-256-CBC | RSA-2048 | ✓ | Wireless Device-to-Device |
| UDP Chat | Ethernet/WiFi | AES-256-CBC | Pre-shared | ✓ | Peer-to-Peer |
| E-Voting | Local | RSA-2048 | Manual | ✓ | Secure Tally |

## Dependencies
```
cryptography
socket (stdlib)
threading (stdlib)
json (stdlib)
os (stdlib)
hashlib (stdlib)
```

## Notes

### Security Considerations
1. **TCP**: Uses OAEP padding with SHA-256 for RSA encryption
2. **UDP**: Requires pre-shared key (not suitable for initial contact)
3. **Voting**: Demonstrates homomorphic properties; production system would use dedicated voting library

### Limitations
- TCP uses fixed ports (not auto-negotiated)
- UDP chat requires pre-shared key (no ECDH for key exchange)
- Voting system uses simplified homomorphic approach for demonstration
- No certificate validation in TCP implementation

### Real-World Extensions
1. Add TLS/SSL for TCP (production: use ssl module)
2. Implement ECDH for UDP key exchange
3. Use dedicated Paillier library for production voting
4. Add timestamp verification to prevent replay attacks
5. Implement message authentication codes (MAC)

## Testing

### TCP Communication Test
```
Server: Listen on localhost:5000
Client: Connect, send encrypted messages
Result: Encrypted messages transmitted securely
```

### UDP Chat Test
```
Chat1: Listen on :5001
Chat2: Listen on :5002
Result: Encrypted peer-to-peer communication
```

### Voting Test
```
Cast multiple votes with different voter IDs
Result: All votes encrypted, tally shows results
```
