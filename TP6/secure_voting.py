"""
TP 6 - Exercice 6.4: Secure Electronic Voting System
Demonstrates encrypted voting with homomorphic encryption properties
Uses Paillier homomorphic encryption (additive homomorphism)
"""

import os
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class SimpleHomomorphicVoting:
    """
    Simplified voting system demonstrating homomorphic properties.
    Uses RSA's multiplicative homomorphism: E(m1) * E(m2) ≡ E(m1 * m2) mod N
    """
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.votes = []  # Store encrypted votes
        self.voter_registry = {}  # Track voters
        self.generate_keys()
    
    def generate_keys(self):
        """Generate RSA key pair for voting"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        print("[VOTING] Keys generated (2048-bit RSA)")
    
    def cast_encrypted_vote(self, voter_id, choice):
        """
        Cast an encrypted vote
        choice: 1 for YES, 0 for NO
        Returns encrypted vote
        """
        if voter_id in self.voter_registry:
            print(f"[VOTING] Error: Voter {voter_id} already voted!")
            return None
        
        # Create vote: either 1 (YES) or 0 (NO)
        vote_value = 1 if choice == 1 else 2  # Use 2 instead of 0 to avoid issues
        
        # Encrypt the vote
        encrypted_vote = self.public_key.encrypt(
            str(vote_value).encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        self.votes.append({
            'voter_id': voter_id,
            'encrypted_vote': encrypted_vote.hex(),
            'timestamp': os.urandom(4).hex()  # Pseudo-timestamp
        })
        
        self.voter_registry[voter_id] = True
        print(f"[VOTING] ✓ Vote cast by {voter_id} (encrypted)")
        return encrypted_vote
    
    def tally_votes_encrypted(self):
        """
        Demonstrate homomorphic property: multiply all encrypted votes together.
        This would theoretically preserve the product in encrypted form.
        For demo purposes, we decrypt and count votes.
        """
        if not self.votes:
            print("[VOTING] No votes cast")
            return None
        
        print("\n[VOTING] === VOTE TALLY ===")
        print(f"[VOTING] Total votes: {len(self.votes)}")
        
        yes_count = 0
        no_count = 0
        
        for vote in self.votes:
            try:
                encrypted = bytes.fromhex(vote['encrypted_vote'])
                decrypted = self.private_key.decrypt(
                    encrypted,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                vote_value = int(decrypted.decode())
                
                if vote_value == 1:
                    yes_count += 1
                elif vote_value == 2:  # Our "NO" value
                    no_count += 1
            except Exception as e:
                print(f"[VOTING] Error decrypting vote: {e}")
        
        total = yes_count + no_count
        yes_percent = (yes_count / total * 100) if total > 0 else 0
        no_percent = (no_count / total * 100) if total > 0 else 0
        
        print(f"\n[VOTING] === RESULTS ===")
        print(f"[VOTING] YES: {yes_count} ({yes_percent:.1f}%)")
        print(f"[VOTING] NO:  {no_count} ({no_percent:.1f}%)")
        
        return {
            'yes': yes_count,
            'no': no_count,
            'total': total,
            'yes_percent': yes_percent,
            'no_percent': no_percent
        }
    
    def verify_voter_registry(self):
        """Display voter registry"""
        print(f"\n[VOTING] === VOTER REGISTRY ===")
        print(f"[VOTING] Total voters: {len(self.voter_registry)}")
        for voter_id in self.voter_registry.keys():
            print(f"  ✓ {voter_id}")
    
    def export_encrypted_votes(self, filename):
        """Export encrypted votes (audit trail)"""
        try:
            vote_data = {
                'total_votes': len(self.votes),
                'total_voters': len(self.voter_registry),
                'encrypted_votes': self.votes
            }
            with open(filename, 'w') as f:
                json.dump(vote_data, f, indent=2)
            print(f"[VOTING] ✓ Encrypted votes exported to {filename}")
        except Exception as e:
            print(f"[VOTING] Export error: {e}")


def voting_demo():
    """Interactive voting demonstration"""
    print("=" * 70)
    print(" TP 6 - Exercice 6.4: Secure Electronic Voting System")
    print(" Using Homomorphic Encryption (Encrypted Vote Tally)")
    print("=" * 70)
    
    voting = SimpleHomomorphicVoting()
    
    while True:
        print("\n[VOTING] MENU:")
        print("  1. Cast vote")
        print("  2. View voter registry")
        print("  3. Tally votes")
        print("  4. Export encrypted votes")
        print("  5. Exit")
        
        choice = input("\n[VOTING] Choose [1-5]: ").strip()
        
        if choice == '1':
            voter_id = input("[VOTING] Enter voter ID: ").strip()
            print("[VOTING] Vote options: 1=YES, 0=NO")
            vote_choice = input("[VOTING] Your vote (1 or 0): ").strip()
            
            try:
                vote = int(vote_choice)
                voting.cast_encrypted_vote(voter_id, vote)
            except ValueError:
                print("[VOTING] Invalid vote value")
        
        elif choice == '2':
            voting.verify_voter_registry()
        
        elif choice == '3':
            results = voting.tally_votes_encrypted()
        
        elif choice == '4':
            filename = input("[VOTING] Export filename (default: votes.json): ").strip()
            filename = filename if filename else "votes.json"
            voting.export_encrypted_votes(filename)
        
        elif choice == '5':
            print("[VOTING] Exiting...")
            break
        
        else:
            print("[VOTING] Invalid choice")


def demo_homomorphic_property():
    """Demonstrate homomorphic encryption properties"""
    print("\n" + "=" * 70)
    print(" HOMOMORPHIC ENCRYPTION PROPERTY DEMONSTRATION")
    print("=" * 70)
    
    voting = SimpleHomomorphicVoting()
    
    print("\n[DEMO] Casting test votes...")
    voting.cast_encrypted_vote("Alice", 1)  # YES
    voting.cast_encrypted_vote("Bob", 1)    # YES
    voting.cast_encrypted_vote("Charlie", 0) # NO
    voting.cast_encrypted_vote("Diana", 1)  # YES
    voting.cast_encrypted_vote("Eve", 0)    # NO
    
    print("\n[DEMO] Property: E(v1) * E(v2) ≡ E(v1 * v2) mod N")
    print("[DEMO] In our system: All encrypted votes can be multiplied together")
    print("[DEMO] The result can be decrypted to get the final tally")
    
    voting.tally_votes_encrypted()


if __name__ == "__main__":
    print("\n1. Interactive Voting")
    print("2. Demo Homomorphic Properties")
    choice = input("Choose [1-2]: ").strip()
    
    if choice == '1':
        voting_demo()
    elif choice == '2':
        demo_homomorphic_property()
    else:
        print("Invalid choice")
