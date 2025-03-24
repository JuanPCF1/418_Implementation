import socket
import threading
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

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