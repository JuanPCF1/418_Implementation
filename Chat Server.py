import socket
import threading

def log_message(message):
    with open("server_log", "a") as log_file:
        log_file.write(message + "\n")

def handle_client(client_socket, clients, username, usernames):
    try:
        # Receive all incoming client messages, and broadcast them to all clients except the client it came from
        while True:
            message = client_socket.recv(1024).decode()
            
            # Separate the client's name from the message
            foo, message_only = message.split(": ", 1)
            log_message(username + ": " + message_only)
            if message_only == "@grove":
                client_socket.sendall(("Users in the grove: " + ", ".join(usernames)).encode())
            else:
                if message_only == "@leaves":
                    raise ConnectionResetError
                for client in clients:
                    if client != client_socket:
                        client.sendall(message.encode())
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
        while True:
            client_socket, addr = server_socket.accept()
            log_message(f"Connection from {addr}")
            new_user = client_socket.recv(1024).decode()
            clients.append(client_socket)
            usernames.append(new_user)
            client_handler = threading.Thread(target=handle_client, args=(client_socket, clients, new_user, usernames))
            client_handler.start()

if __name__ == "__main__":
    main()