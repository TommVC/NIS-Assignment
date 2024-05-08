import socket


def connect_ca():
    # create a socket object
    ca_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    ca_ip = "127.0.0.1"  # replace with the server's IP address
    ca_port = 8003  # replace with the server's port number
    # establish connection with server
    ca_send.connect((ca_ip, ca_port))

    while True:
        # input message and send it to the server
        msg = input("Enter message to CA: ")
        ca_send.send(msg.encode("utf-8")[:1024])

        # receive message from the server
        response = ca_send.recv(1024)
        response = response.decode("utf-8")

        # if server sent us "closed" in the payload, we break out of the loop and close our socket
        if response.lower() == "closed":
            break

        print(f"Received: {response}")

    # close client socket (connection to the server)
    ca_send.close()
    print("Connection to CA closed")


def connect():
    # create a socket object
    sendSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    serverIP = "127.0.0.1"  # replace with the server's IP address
    serverPort = 8002  # replace with the server's port number
    # establish connection with server
    sendSocket.connect((serverIP, serverPort))
    count = 1

    name = input("Enter username: ")
    sendSocket.send(name.encode("utf-8")[:1024])
    response = sendSocket.recv(1024)
    response = response.decode("utf-8")
    print(response)
    while True:
        if not("No available clients" in response):
            print(response)
            msg = input("Choose who to message: ")
            index = 0
            if not msg == "close":
                index = eval(msg) - 1
                
            sendSocket.send(msg.encode("utf-8")[:1024])

            # receive message from the server
            response = sendSocket.recv(1024)
            response = response.decode("utf-8")
            print(response)
            msg = input()
            sendSocket.send(msg.encode("utf-8")[:1024])

            response = sendSocket.recv(1024)
            response = response.decode("utf-8")
            print(response)
            # if server sent us "closed" in the payload, we break out of the loop and close our socket
            if response.lower() == "closed":
                break
        else:
            response = sendSocket.recv(1024)
            response = response.decode("utf-8")

    # close client socket (connection to the server)
    sendSocket.close()
    print("Connection to server closed")

connect()