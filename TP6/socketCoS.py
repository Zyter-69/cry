import socket
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
    key_cipher = rsa.encrypt(key, Spk) #Spk est la clé publique de B
    return (cipher_hex, msg_signature, key_cipher)

def traite_msg_recu(cipher_msg , signature, key_cipher, private_key, Cpk):
    key = rsa.decrypt(key_cipher, private_key)
    message = des.decrypt(cipher_msg, key)
    hash_signed = des.decrypt(signature, key)
    if rsa.decrypt(eval(hash_signed), Cpk) != MD5(message):
        client_socket.send("Message mal reçu.".encode('utf-8'))
    else:
        print("Message reçu de B !")
        return message 


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

HOST = 'localhost'
PORT = 5000
server_socket.bind((HOST, PORT))

server_socket.listen(1)


client_socket, client_address = server_socket.accept()
print(f"Connection established with {client_address}")


try:
    p = rsa.generate_prime()
    q = rsa.generate_prime()
    private_key , public_key = rsa.generate_keys(p, q)
    Cpk = pickle.loads(client_socket.recv(1024))
    client_socket.send(pickle.dumps(public_key))
    while True:
        reponse=client_socket.recv(1024)
        try:
            cipher_msg , signature, key_cipher = pickle.loads(reponse)
        except Exception as e:
            print("Error processing message mnich hna")
            print(reponse.decode('utf-8'))
            continue
        print("B :" + traite_msg_recu(cipher_msg , signature, key_cipher, private_key, Cpk))
        message = input("Enter message: ")
        cipher_msg = traite_msg_a_enoyer(message, Cpk, private_key)
        client_socket.send(pickle.dumps(cipher_msg))
finally:
    client_socket.close()
    server_socket.close()
    print("Server closed")