import socket
from TP2 import des
from TP3 import rsa
from TP4.MD5 import MD5
import os
import pickle

def traite_msg_a_enoyer(message, Spk, private_key):
    hash_value = MD5(message)
    hash_signed = rsa.encrypt(hash_value, private_key)
    key = os.urandom(8).hex()
    cipher_hex = des.encrypt(message, key)
    msg_signature = des.encrypt(str(hash_signed), key)
    key_cipher = rsa.encrypt(key, Spk)
    return (cipher_hex, msg_signature, key_cipher)

def traite_msg_recu(cipher_msg , signature, key_cipher, private_key, Spk):
    key = rsa.decrypt(key_cipher, private_key)
    message = des.decrypt(cipher_msg, key)
    hash_signed = des.decrypt(signature, key)
    if rsa.decrypt(eval(hash_signed), Spk) != MD5(message):
        client_socket.send("Message mal reçu.".encode('utf-8'))
    else:
        print("Message reçu de A !")
        return message 


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

HOST = 'localhost'
PORT = 5000
client_socket.connect((HOST, PORT))
print(f"Connected to with {HOST}:{PORT}")

try:
    p = rsa.generate_prime()
    q = rsa.generate_prime()
    private_key , public_key = rsa.generate_keys(p, q)
    client_socket.send(pickle.dumps(public_key))
    Spk = pickle.loads(client_socket.recv(1024))
    while True:
        message = input("Enter message: ")
        cipher_msg = traite_msg_a_enoyer(message, Spk, private_key)
        client_socket.send(pickle.dumps(cipher_msg))
        reponse=client_socket.recv(1024)
        try:
            cipher_msg , signature, key_cipher = pickle.loads(reponse)
        except Exception as e:
            print("Error processing message mnich hna")
            print(reponse.decode('utf-8'))
            continue
        print("A :" + traite_msg_recu(cipher_msg , signature, key_cipher, private_key, Spk))
finally:
    client_socket.close()
    print("Disconnected from server")