import hashlib
import hmac
import socket
import sys
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
    def __init__(self, parameters=None):
        # If parameters are provided, use them, otherwise generate new parameters
        if parameters:
            self.parameters = parameters
        else:
            # This will only be used if parameters aren't passed from the server
            self.parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        
        # Generate a private key and public key pair
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
        
        # Variables to keep track of the state of the ratchet
        self.root_key = None
        self.chain_key_send = None
        self.chain_key_receive = None
        self.message_number_send = 0
        self.message_number_receive = 0
        
        # Stores the remote party's current public key
        self.remote_public_key = None
        
        # Flag to track if we've sent our first message yet
        self.sent_first_message = False
        
        # Flag to determine if we're the initiator (affects key derivation)
        self.is_initiator = False
    
    def generate_shared_key(self, server_public_key):
        # Generate a shared key using the server's public key and our private key
        shared_key = self.private_key.exchange(server_public_key)
        return shared_key
        
    def derive_keys(self, shared_key, is_initiator=False):
        # Derive the root key from the shared key using HKDF
        self.derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=96,  # Increase to have enough bytes for all keys
            salt=None,
            info=b'Diffie-Hellman key derivation using HKDF',
            backend=default_backend()
        ).derive(shared_key)
        
        # Use the derived key to create the root key and chain keys
        self.root_key = self.derived_key[:32]  # 32 bytes for root key
        
        # The initiator (first client) and responder (second client) use reversed chain keys
        if is_initiator:
            # First client uses first part for sending, second part for receiving
            self.chain_key_send = self.derived_key[32:64]  # 32 bytes for sending chain
            self.chain_key_receive = self.derived_key[64:]  # 16 bytes for receiving chain
        else:
            # Second client uses first part for receiving, second part for sending
            self.chain_key_receive = self.derived_key[32:64]  # 32 bytes for receiving chain
            self.chain_key_send = self.derived_key[64:]  # 16 bytes for sending chain

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
        
    def dh_ratchet_send(self):
        """
        Performs the sending part of a DH ratchet:
        1. Generates a new key pair
        2. Calculates a new shared secret using the remote public key
        3. Derives new chain keys from this shared secret
        """
        # Generate a new key pair
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
                
        # Calculate new shared secret
        if self.remote_public_key:
            shared_key = self.private_key.exchange(self.remote_public_key)
            
            # Use HKDF to derive new root key and chain keys
            kdf = HKDF(
                algorithm=hashes.SHA256(),
                length=96,  # 32 bytes for root key + 32 for send chain + 16 for receive chain
                salt=self.root_key,  # Use the current root key as salt
                info=b'DH Ratchet update',
                backend=default_backend()
            )
            derived_key = kdf.derive(shared_key)
            
            # Update the root key and chain keys
            self.root_key = derived_key[:32]
            
            # Assign chain keys based on initiator status
            if self.is_initiator:
                self.chain_key_send = derived_key[32:64]
                self.chain_key_receive = derived_key[64:]
            else:
                self.chain_key_receive = derived_key[32:64]
                self.chain_key_send = derived_key[64:]
                
            return True
        return False
        
    def dh_ratchet_receive(self, new_remote_key):
        # Store the new remote public key
        self.remote_public_key = new_remote_key
                
        # Calculate new shared secret using our current private key
        shared_key = self.private_key.exchange(self.remote_public_key)
        
        # Use HKDF to derive new root key and chain keys
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=96,  # 32 bytes for root key + 32 for send chain + 16 for receive chain
            salt=self.root_key,  # Use the current root key as salt
            info=b'DH Ratchet update',
            backend=default_backend()
        )
        derived_key = kdf.derive(shared_key)
        
        # Update the root key and chain keys
        self.root_key = derived_key[:32]
        
        # Assign chain keys based on initiator status
        if self.is_initiator:
            self.chain_key_send = derived_key[32:64]
            self.chain_key_receive = derived_key[64:]
        else:
            self.chain_key_receive = derived_key[32:64]
            self.chain_key_send = derived_key[64:]
            
        return True
    
    def encrypt_message(self, plaintext):
        # Before encrypting, perform a DH ratchet if this is not our first message
        if self.sent_first_message:
            self.dh_ratchet_send()
        else:
            self.sent_first_message = True
            
        # Encode the public key to include with the message
        public_key_bytes = self.public_key.public_numbers().y.to_bytes((2048+7) // 8, byteorder='big')
        public_key_hex = public_key_bytes.hex()
        
        # Encrypt the message using the current message key
        message_key = self.ratchet_forward(is_sending=True)
        
        # Generate a fixed-length key and IV from the message key
        encryption_key = message_key[:32]  # Use first 32 bytes as the key
        
        # Generate a 16-byte IV
        iv_material = hmac.new(message_key, b"iv", hashlib.sha256).digest()
        iv = iv_material[:16]  # Take exactly 16 bytes for the IV

        # Create cipher object and encrypt the message
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad the message
        padded_message = self.pad(plaintext.encode())

        # Encrypt the message
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        encrypted_text = b64encode(ciphertext).decode()
        
        # Combine the public key and ciphertext in a JSON structure
        message_packet = json.dumps({
            "public_key": public_key_hex,
            "ciphertext": encrypted_text
        })
        
        return message_packet
    
    def decrypt_message(self, received_message):
        try:
            # Parse the received message packet
            message_data = json.loads(received_message)
            
            # Extract remote public key and ciphertext
            remote_public_key_hex = message_data.get("public_key")
            encoded_ciphertext = message_data.get("ciphertext")
            
            if not remote_public_key_hex or not encoded_ciphertext:
                print("Error: Received message is missing public key or ciphertext")
                return "Error: Invalid message format"
                
            # Reconstruct the remote public key
            remote_y = int(remote_public_key_hex, 16)
            remote_public_numbers = dh.DHPublicNumbers(
                y=remote_y,
                parameter_numbers=self.parameters.parameter_numbers()
            )
            new_remote_public_key = remote_public_numbers.public_key(default_backend())
            
            # Check if the remote public key has changed
            key_changed = False
            if self.remote_public_key is None or (
                    self.remote_public_key.public_numbers().y != new_remote_public_key.public_numbers().y):
                key_changed = True
                
                # Perform a DH ratchet receive step if the key has changed
                if key_changed and self.root_key is not None:
                    self.dh_ratchet_receive(new_remote_public_key)
                else:
                    # Just store the new key if this is our first message
                    self.remote_public_key = new_remote_public_key
            
            # Generate the next message key by driving the ratchet forward
            message_key = self.ratchet_forward(is_sending=False)

            # Generate a fixed-length key and IV from the message key
            decryption_key = message_key[:32]
            
            # Generate the same 16-byte IV using the same method
            iv_material = hmac.new(message_key, b"iv", hashlib.sha256).digest()
            iv = iv_material[:16]  # Take exactly 16 bytes for the IV

            # Create cipher object and decrypt the message
            cipher = Cipher(algorithms.AES(decryption_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            # Decode and decrypt
            ciphertext = b64decode(encoded_ciphertext)
            decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

            # Unpad the message and return
            return self.unpad(decrypted_message).decode()
            
        except json.JSONDecodeError:
            print("Error: Could not parse message as JSON")
            return "Error: Invalid message format"
        except Exception as e:
            print(f"Error decrypting message: {e}")
            return f"Error: {str(e)}"
    
    def pad(self, s):
        # Uses PKCS7 padding to pad the message to a multiple of the block size
        padding_length = 16 - (len(s) % 16)
        padding = bytes([padding_length] * padding_length)
        return s + padding
    
    def unpad(self, s):
        # Removes PKCS7 padding from the message
        padding_length = s[-1]
        
        # Validate the padding to ensure it's correct
        if padding_length > 16:  # Sanity check - padding can't be larger than block size
            return s  # Return as-is if padding seems invalid
            
        # Verify all padding bytes have the correct value
        valid_padding = True
        for i in range(1, padding_length + 1):
            if s[-i] != padding_length:
                valid_padding = False
                break
                
        if not valid_padding:
            print("Warning: Invalid padding detected")
            return s  # Return as-is if padding is invalid
            
        # Remove the padding if it's valid
        return s[:-padding_length]
        

def receive_messages(client_socket, double_ratchet):
    while True:
        try:
            # Receive the incoming message from the server
            response = client_socket.recv(2048).decode()  # Increased buffer size for JSON+key
            
            if not response:
                continue
                
            # Attempt to decrypt the message
            try:
                decrypted_message = double_ratchet.decrypt_message(response)
                print(decrypted_message)
            except Exception as e:
                print(f"Failed to decrypt message: {e}")
                print(f"Error details: {str(e)}")
        except ConnectionResetError:
            print("Connection closed by server")
            break
        except Exception as e:
            print(f"Error receiving message: {e}")
            continue

def main():
    host = '127.0.0.1'
    port = 12345

    # We'll initialize double_ratchet after receiving parameters from server
    double_ratchet = None

    # Ask the user for a username
    user_name = input("Enter your name: ")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            # Connect to the server
            client_socket.connect((host, port))

            # Send the username to the server (No need to encrypt a public username)
            client_socket.sendall(user_name.encode())

            # Wait for the server to acknowledge the username
            server_ACK = client_socket.recv(1024).decode()
            if server_ACK != "ALLGOOD":
                print("Something's wrong with the server....")
                return
            
            # Receive DH parameters from the server
            params_json = json.loads(client_socket.recv(2048).decode())
            print(f"Waiting for other user to connect...")
            
            # Acknowledge receipt of parameters
            client_socket.sendall("PARAMS_RECEIVED".encode())
            
            # Create DH parameters from the received values
            parameter_numbers = dh.DHParameterNumbers(
                p=int(params_json['p']),
                g=params_json['g']
            )
            parameters = parameter_numbers.parameters(default_backend())
            
            # Now initialize the DoubleRatchet with the server-provided parameters
            double_ratchet = DoubleRatchet(parameters)
            
            # Send only the public key to the server
            public_key_bytes = double_ratchet.public_key.public_numbers().y.to_bytes((2048+7) // 8, byteorder='big')
            client_socket.sendall(json.dumps({
                'public_key': public_key_bytes.hex()
            }).encode())

            # Receive remote public key information
            remote_params = json.loads(client_socket.recv(2048).decode())

            # Reconstruct the remote public key using our parameters
            remote_public_numbers = dh.DHPublicNumbers(
                y=int(remote_params['public_key'], 16),
                parameter_numbers=parameter_numbers
            )
            remote_public_key = remote_public_numbers.public_key(default_backend())

            # Store the remote public key
            double_ratchet.remote_public_key = remote_public_key

            # Generate the shared key and derive the keys
            shared_key = double_ratchet.generate_shared_key(remote_public_key)
            
            # Determine if this client is the initiator (first client)
            is_initiator = False
            if len(remote_params.get('is_initiator', '')) > 0:
                is_initiator = not bool(int(remote_params['is_initiator']))
            
            # Store the initiator status in the double ratchet
            double_ratchet.is_initiator = is_initiator
                
            double_ratchet.derive_keys(shared_key, is_initiator)

            print(f"Connected to chat client {host}:{port}, say hi!\n You can exit the chat by typing @exit")
            
            # Make a new thread to handle incoming messages
            message_receiver = threading.Thread(target=receive_messages, args=(client_socket, double_ratchet))
            message_receiver.daemon = True  # Daemonize thread to exit when main thread exits
            message_receiver.start()

            session = PromptSession(message=f"{user_name}: ")
            with patch_stdout():
                while True:
                    message_input = session.prompt()
                    

                    if not message_input.strip():
                        continue

                    # Give the user a chance to exit the chat
                    if message_input == "@exit":
                        print("Exiting chat...")
                        message_receiver
                        sys.exit(0)

                    # Encrypt the message and send (now includes public key in JSON)
                    message_packet = double_ratchet.encrypt_message(f"{user_name}: " + message_input)
                    client_socket.sendall(message_packet.encode())
                
        except ConnectionRefusedError:
            print(f"Connection to {host}:{port} failed. Ensure the server is running.")
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()