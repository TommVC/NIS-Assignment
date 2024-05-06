import socket
import threading

#arrays to track all clients connected and their usernames
clients = []
names = []

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
     # receive username from the client
    name = client_socket.recv(1024)
    name = name.decode("utf-8")
    names.append(name)
    print(names)
    # accept incoming connections
    print(f"Accepted connection from {name}")

    response = "[SERVER]: Connected"
    client_socket.send(response.encode("utf-8"))

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

        print(request)

        response = "[SERVER]: received".encode("utf-8")  # convert string to bytes
        # convert and send accept response to the client
        client_socket.send(response)

    # close connection socket with the client
    clients.remove(client_socket)
    names.remove(name)
    client_socket.close()
    print(f"Connection to {name} closed")


if __name__ == "__main__":
    while True:
        client_socket, client_address = listen_socket.accept()
        clients.append(client_socket)
        print(clients)
        thread = threading.Thread(target=connectClient,args=(client_socket, client_address))
        thread.start()