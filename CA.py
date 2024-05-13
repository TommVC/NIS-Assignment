import socket
import threading
import queue
from rsa_python import rsa

KEY_PAIR = rsa.generate_key_pair(1024)  # Generates public key immediately
HOST = "127.0.0.1"
PORT = 8003

# Create a queue to store waiting clients
client_queue = queue.Queue()


def handle_client(conn, addr):
    print(f'Connected by {addr}')
    while True:
        name = conn.recv(1024)
        name = name.decode("utf-8")
        print("recived name " + name)

        pk = conn.recv(1024)  # public key # public modulus
        pk = pk.decode("utf-8")
        print("recived pk " + pk)

        pm = conn.recv(1024)  # public modulus
        pm = pm.decode("utf-8")
        print("recived modulus " + pm)

        response = "This public key belongs to " + name + "," + pk + "," + pm
        conn.send(response.encode("utf-8"))

        response = str(KEY_PAIR["public"]) + "," + str(KEY_PAIR["modulus"])
        conn.send(response.encode("utf-8"))

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