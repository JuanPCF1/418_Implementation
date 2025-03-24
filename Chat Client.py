import socket
import threading
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
import random

def receive_messages(client_socket,):
    while True:
        response = client_socket.recv(1024).decode()
        print(response)

def main():
    host = '127.0.0.1'
    port = 12345
    panda_facts = [
    "Pandas have a special 'thumb'—an extended wrist bone—that helps them grasp bamboo.",
    "Despite being classified as carnivores, pandas eat almost exclusively bamboo, consuming up to 40 kg (88 lbs) per day!",
    "Newborn pandas are about the size of a stick of butter and weigh only around 100 grams (3.5 ounces).",
    "Pandas do handstands while urinating to mark their territory at higher points on trees!",
    "Unlike most bears, pandas do not hibernate because their bamboo diet doesn’t provide enough fat storage.",
    "Each panda has unique fur patterns, just like human fingerprints!",
    "Pandas can swim and climb trees, even as cubs, making them more agile than they seem.",
    "Ancient Chinese emperors kept pandas as rare and exotic pets, believing they had mystical powers.",
    "Pandas sometimes somersault and play just for fun, making them one of the most playful bear species.",
    "The black and white fur pattern helps pandas blend into their environment—white for snow and black for shadows in forests."]

    
    user_name = input("Enter your name: ")
    if (user_name[-1].lower() != 'a'):
        user_name += "anda"
    else:
        user_name += "nda"
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((host, port))
            client_socket.sendall(user_name.encode())
            print(f"Connected to chat client {host}:{port}, say hi!")
            
            # Make a new thread to handle incoming messages
            message_receiver = threading.Thread(target=receive_messages, args=(client_socket,))
            message_receiver.start()

            session = PromptSession(message=f"{user_name}🐼: ")
            with patch_stdout():
                while True:
                    message_input = session.prompt()

                    if message_input.lower() == "@bamboo":
                        # Print a random panda fact for the user
                        print(panda_facts[random.randint(0, len(panda_facts) - 1)])
                        
                    # Send the input to the server
                    client_socket.sendall((f"{user_name}🐼: " + message_input).encode())
                
        except ConnectionRefusedError:
            print(f"Connection to {host}:{port} failed. Ensure the server is running.")
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()