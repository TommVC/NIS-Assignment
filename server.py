import socket
import threading

#arrays to track all clients connected and their usernames
clients = []
names = []
numClients = 0

# create a socket object
listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ip = "127.0.0.1"
port = 8002
# bind the socket to a specific address and port
listen_socket.bind((ip, port))
# listen for incoming connections 
listen_socket.listen(0)
print(f"Listening on {ip}:{port}")

def getClientList(clientNum):
    if len(names) > 1:
        response = "[SERVER]: Connected\nAvailable Clients:"
        for i in range(len(names)):
            if not i == clientNum:
                response = str(i+1) + ". " + names[i]
    else:
        response = "No available clients"
    return response

def connectClient(client_socket, client_address, clientNum):
     # receive username from the client
    name = client_socket.recv(1024)
    name = name.decode("utf-8")
    names.append(name)
    print(names)
    # accept incoming connections
    print(f"Accepted connection from {name}")
    response = getClientList(clientNum)
    client_socket.send(response.encode("utf-8"))

    while True:
        if not(response == "No available clients"):
            request = client_socket.recv(1024)
            request = request.decode("utf-8")  # convert bytes to string

            # if we receive "close" from the client, then we break
            # out of the loop and close the conneciton
            if request.lower() == "close":
                # send response to the client which acknowledges that the
                # connection should be closed and break out of the loop
                client_socket.send("closed".encode("utf-8"))
                break

            index = eval(request) - 1

            response = ("[SERVER]: What message would you like to send to " + names[index] + "?").encode("utf-8")  # convert string to bytes
            # convert and send accept response to the client
            client_socket.send(response)

            msg = client_socket.recv(1024)
            msg = msg.decode("utf-8")
            clients[index].send(("[" + name + "]: " + msg).encode("utf-8"))
            client_socket.send("[SERVER]: Message sent".encode("utf-8"))
            
        else:
            response = getClientList(clientNum)
            client_socket.send(response.encode("utf-8"))

    # close connection socket with the client
    clients.remove(client_socket)
    names.remove(name)
    numClients = numClients - 1
    client_socket.close()
    print(f"Connection to {name} closed")


if __name__ == "__main__":
    while True:
        client_socket, client_address = listen_socket.accept()
        clients.append(client_socket)
        print(clients)
        thread = threading.Thread(target=connectClient,args=(client_socket, client_address, numClients))
        numClients+=1
        thread.start()