import socket
import threading
import os
import json
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

class DoubleRatchet:
    def __init__(self):
        # Set up the diffie-hellman parameters using the cryptography library
        self.parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
        
        # Generate a private key and private key pair
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
        
        # Variables to keep track of the state of the ratchet
        self.root_key = None
        self.chain_key_send = None
        self.chain_key_receive = None
        self.message_number_send = 0
        self.message_number_receive = 0
        
        # Storest the public key we will get from the server
        self.server_public_key = None
    
    def generate_shared_key(self, server_public_key):
        # Generate a shared key using the server's public key and our private key
        shared_key = self.private_key.exchange(server_public_key)
        
    def derive_keys(self, shared_key):
        # Derive the root key from the shared key using HKDF
        self.derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'Diffie-Hellman key derivation using HKDF',
            backend=default_backend()
        ).derive(shared_key)
        
        # Use the derived key to create the root key and chain keys
        self.root_key = self.derived_key[:32]
        self.chain_key_send = self.derived_key[32:48]
        self.chain_key_receive = self.derived_key[48:]
        

# Parameters for the diffie-hellman key exchange
parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())


def encrypt_message(message, key):
    init_vector = os.urandom(16)

def receive_messages(client_socket,):
    while True:
        response = client_socket.recv(1024).decode()
        print(response)

def main():
    host = '127.0.0.1'
    port = 12345
    user_name = input("Enter your name: ")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((host, port))
            client_socket.sendall(user_name.encode())
            print(f"Connected to chat client {host}:{port}, say hi!")
            
            # Make a new thread to handle incoming messages
            message_receiver = threading.Thread(target=receive_messages, args=(client_socket,))
            message_receiver.start()

            session = PromptSession(message=f"{user_name}: ")
            with patch_stdout():
                while True:
                    message_input = session.prompt()
                        
                    # Send the input to the server
                    client_socket.sendall((f"{user_name}: " + message_input).encode())
                
        except ConnectionRefusedError:
            print(f"Connection to {host}:{port} failed. Ensure the server is running.")
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()