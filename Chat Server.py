import socket
import threading
import json
import time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

def log_message(message):
    with open("server_log", "a") as log_file:
        log_file.write(message + "\n")

def handle_client(client_socket, clients, username, usernames):
    try:
        # Receive all incoming client messages, and broadcast them to all clients except the client it came from
        while True:
            encrypted_message = client_socket.recv(1024).decode()

            # Log the encrypted message
            log_message(f"Encrypted message from {username}: {encrypted_message}")

            
            
            # Broadcast the message to all other clients
            for client in clients:
                if client != client_socket:
                    client.sendall(encrypted_message.encode())
    except ConnectionResetError:
        log_message(f"{username} disconnected")
        for client in clients:
            if client != client_socket:
                client.sendall(f"{username} disconnected".encode())
        clients.remove(client_socket)
        client_socket.close()

def main():
    host = '127.0.0.1'
    port = 12345

    # Create a socket and bind it to the address
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(5)  # Listen for incoming connections
        print(f"Chat server is running on {host}:{port}...")
        log_message(f"Chat server is running on {host}:{port}...")
        log_message("Server log:")
        clients = []
        usernames = []

        # Track publice keys for key exchange
        client_public_keys = {}

        # Accept incoming connections and handle them in a new thread
        while True:
            client_socket, addr = server_socket.accept()
            log_message(f"Connection from {addr}")

            # Recieve the username to track it
            new_user = client_socket.recv(1024).decode()
            log_message(f"New user connected: {new_user}")

            # Send an acknowledgment to the client
            client_socket.sendall("ALLGOOD".encode())

            # Recieve the public key parameters and public key from the client
            client_key_info_unloaded = client_socket.recv(2048).decode()
            time.sleep(0.1)  # Small delay to ensure the message is received completely
            client_key_info = json.loads(client_key_info_unloaded)
            log_message(f"Public key info from {new_user}: {client_key_info}")
            client_public_keys[new_user] = client_key_info

            # Once we have 2 clients, perform key exchange
            if len(clients) > 0:
                # Get the first client's public key information
                other_client_name = usernames[0]
                other_client_info = client_public_keys[other_client_name]

                # Send each client the other's public key information
                clients[0].sendall(json.dumps(client_key_info).encode())
                client_socket.sendall(json.dumps(other_client_info).encode())
            
            clients.append(client_socket)
            usernames.append(new_user)

            print("Reached the client handler")
            client_handler = threading.Thread(target=handle_client, args=(client_socket, clients, new_user, usernames))
            client_handler.start()

if __name__ == "__main__":
    main()