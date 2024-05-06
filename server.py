import socket
import threading
# create a socket object
listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ip = "127.0.0.1"
port = 8002

# bind the socket to a specific address and port
listen_socket.bind((ip, port))
# listen for incoming connections
listen_socket.listen(0)
print(f"Listening on {ip}:{port}")

def connectClient(client_socket, client_address):
    # accept incoming connections
    print(f"Accepted connection from {client_address[0]}:{client_address[1]}")
     # receive data from the client
    while True:
        request = client_socket.recv(1024)
        request = request.decode("utf-8")  # convert bytes to string

        # if we receive "close" from the client, then we break
        # out of the loop and close the conneciton
        if request.lower() == "close":
            # send response to the client which acknowledges that the
            # connection should be closed and break out of the loop
            client_socket.send("closed".encode("utf-8"))
            break

        print(f"Received: {request}")

        response = "accepted".encode("utf-8")  # convert string to bytes
        # convert and send accept response to the client
        client_socket.send(response)

    # close connection socket with the client
    client_socket.close()
    print("Connection to Alice closed")

if __name__ == "__main__":
    while True:
        client_socket, client_address = listen_socket.accept()
        thread = threading.Thread(target=connectClient,args=(client_socket, client_address))
        thread.start()