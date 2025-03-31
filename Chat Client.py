import hashlib
import hmac
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

    def ratchet_forward(self, is_sending):
        # Derives a new key for sending or receiving messages, driving the ratchet forward
        if is_sending:
            # Derive a new sending chain key and message key
            new_chain_key = hmac.new(self.chain_key_send, b'\x01', hashlib.sha256).digest()
            message_key = hmac.new(self.chain_key_send, b'\x02', hashlib.sha256).digest()
            self.chain_key_send = new_chain_key
            self.message_number_send += 1
            return message_key
        else:
            # Derive a new receiving chain key and message key
            new_chain_key = hmac.new(self.chain_key_receive, b'\x01', hashlib.sha256).digest()
            message_key = hmac.new(self.chain_key_receive, b'\x02', hashlib.sha256).digest()
            self.chain_key_receive = new_chain_key
            self.message_number_receive += 1
            return message_key
        
    def encrypt_message(self, plaintext):
        # Encrypts a message using the current message key and the chain key
        message_key = self.ratchet_forward(is_sending=True)
        
        # Use the first 32 bytes as the encryption key and the next 16 bytes as the IV
        encryption_key = message_key[:32]
        iv = message_key[32:48]

        # Create cipher object and encrypt the message
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad the message
        padded_message = self.pad(plaintext.encode())

        # Encrypt the message and decode
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        return b64encode(ciphertext).decode()
    
    def decrypt_message(self, encoded_ciphertext):
        # Decrypts a message using the current message key and the chain key
        # Generate the next message key by driving the ratchet forward
        message_key = self.ratchet_forward(is_sending=False)

        # Use the first 32 bytes as the decryption key and the next 16 bytes as the IV
        decryption_key = message_key[:32]
        iv = message_key[32:48]

        # Create cipher object and decrypt the message
        cipher = Cipher(algorithms.AES(decryption_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decode and decrypt
        ciphertext = b64decode(encoded_ciphertext)
        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad the message and return
        return self.unpad(decrypted_message).decode()
    
    def _pad(self, s):
        # Uses PKCS7 padding to pad the message to a multiple of the block size
        padding_length = 16 - (len(s) % 16)
        padding = bytes([padding_length] * padding_length)
        return s + padding
    
    def _unpad(self, s):
        # Removes PKCS7 padding from the message
        padding_length = s[-1]
        return s[:-padding_length]
        


def receive_messages(client_socket,double_ratchet):
    while True:
        try:
            # Receive the incoming message from the server
            response = client_socket.recv(1024).decode()
            
            # Attempt to decrypt the message
            try:
                decrypted_message = double_ratchet.decrypt_message(response)
                print(decrypted_message)
            except Exception as e:
                print(f"Failed to decrypt message: {e}")
        except ConnectionResetError:
            print("Connection closed by server")
            break

def main():
    host = '127.0.0.1'
    port = 12345

    # Initialize the double ratchet protocol
    double_ratchet = DoubleRatchet()

    # Ask the user for a username
    user_name = input("Enter your name: ")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            # Connect to the server
            client_socket.connect((host, port))

            # Send the username to the server (No need to encrypt a public username)
            client_socket.sendall(user_name.encode())

            # Send the public key parameters and public key to the server
            parameters_bytes = double_ratchet.parameters.parameter_numbers()
            public_key_bytes = double_ratchet.public_key.public_numbers().y.to_bytes((2048+7) // 8, byteorder='big')

            # Send parameter information to the server
            client_socket.sendall(json.dumps({
                'p': parameters_bytes.p,
                'g': parameters_bytes.g,
                'public_key': public_key_bytes.hex()
            }).encode())

            # Recieve remote public key information
            remote_params = json.loads(client_socket.recv(2048).decode())

            # Reconstruct the server's public key
            remote_params_object = dh.DHParameterNumbers(
                p=remote_params['p'],
                g=remote_params['g']
            ).parameters(default_backend())

            remote_public_key = remote_params_object.load_public_numbers(
                dh.DHPublicNumbers(
                    y=int(remote_params['public_key'], 16),
                    parameter_numbers=remote_params_object.parameter_numbers()
                )
            )

            # Store the remote public key
            double_ratchet.server_public_key = remote_public_key

            # Generate the shared key and derive the keys
            shared_key = double_ratchet.generate_shared_key(remote_public_key)
            double_ratchet.derive_keys(shared_key)

            print(f"Connected to chat client {host}:{port}, say hi!")
            
            # Make a new thread to handle incoming messages
            message_receiver = threading.Thread(target=receive_messages, args=(client_socket,))
            message_receiver.start()

            session = PromptSession(message=f"{user_name}: ")
            with patch_stdout():
                while True:
                    message_input = session.prompt()
                        
                    # Encrypt the message and send
                    encrypted_message = double_ratchet.encrypt_message(f"{user_name}: " + message_input)
                    client_socket.sendall(encrypted_message.encode())
                
        except ConnectionRefusedError:
            print(f"Connection to {host}:{port} failed. Ensure the server is running.")
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()