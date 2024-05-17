import socket
import threading
import queue
import time
import Hashing as hash
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256

HOST = "127.0.0.1"
PORT = 8003

# Create a queue to store waiting clients
client_queue = queue.Queue()

privateKey = RSA.generate(3072)


def handle_client(conn, addr):
    print(f'Connected by {addr}')
    while True:
        name = conn.recv(1024)
        name = name.decode("utf-8")

        pk = conn.recv(1024)  # public key
        print("\nRECEIVED NAME + PK:" + name + " " + str(pk) + "\n")


        response = name + "#" + pk.decode("utf-8")
        response = response.encode('utf-8')
        
        h = SHA256.new(response)
        signature = pss.new(privateKey).sign(h)


        conn.send(response)
        time.sleep(1)
        conn.send(signature)
        time.sleep(1)
        print("\nSENT CERTIFICATE AND SIGNATURE: " + str(response) + "\n" + str(signature) + "\n")

        response = privateKey.public_key().exportKey()
        conn.send(response)
        print("\nSENT CA: " + str(response) + "\n")

        break
    conn.close()
    print(f'Client {addr} closed connection')
    # Signal the next client in line (if any)
    client_queue.put(True)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f'Server listening on {HOST}:{PORT}')
        while True:
            # Accept a new client connection
            conn, addr = s.accept()
            # Check if there are waiting clients
            if not client_queue.empty():
                # Notify the waiting client that it can connect now
                client_queue.get(timeout=1)  # Wait with timeout to avoid blocking
            # Start a new thread to handle the client connection
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()


if __name__ == '__main__':
    main()