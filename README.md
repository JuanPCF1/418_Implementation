# 418_Implementation

This is a chat server/client combo that simulates end-to-end encrypted chat which can be tested for vulnerabilities and functionality.
It implements the double-ratchet algorithm using a Diffie-Hellman ratchet to refresh the keys after every message

How to run:

1. Make sure both the "Chat Server.py" and "Chat_Client.py" files are downloaded on your computer
2. Run the "Chat Server.py" file on a terminal, and wait for the message telling you it is running
3. Run 2 "Chat_Client.py" scripts on different terminals to model 2 clients
4. You may now message back and forth securely with both clients
5. To exit, type "@exit" in the chat and send it
6. If you wish to re-test the implementation, make sure you re-run the server as well.

Known Limitations:

- Only 2 users are allowed at a time
- Support only for UTF-8 text messages
- No authentication support

Potential Issues:
- If it says you do not have the cryptography library please run the following commands:
On windows:
pip install cryptography

On Linux:
sudo apt install cyrptography

