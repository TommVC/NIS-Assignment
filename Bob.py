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


def connect_alice():
    # create a socket object
    bob_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    alice_ip = "127.0.0.1"  # replace with the server's IP address
    alice_port = 8000  # replace with the server's port number
    # establish connection with server
    bob_send.connect((alice_ip, alice_port))

    count = 1

    while True:
        # input message and send it to the server
        msg = input("Enter message to Alice: ")
        bob_send.send(msg.encode("utf-8")[:1024])

        # receive message from the server
        response = bob_send.recv(1024)
        response = response.decode("utf-8")

        # if server sent us "closed" in the payload, we break out of the loop and close our socket
        if response.lower() == "closed":
            break

        print(f"Received: {response}")

        if count == 1:
            connect_ca()
            count = 0

    # close client socket (connection to the server)
    bob_send.close()
    print("Connection to Alice closed")


def run_bob():

    # create a socket object
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    bob_ip = "127.0.0.1"
    port = 8002

    # bind the socket to a specific address and port
    listen_socket.bind((bob_ip, port))
    # listen for incoming connections
    listen_socket.listen(0)
    print(f"Listening on {bob_ip}:{port}")

    # accept incoming connections
    alice_socket, alice_address = listen_socket.accept()
    print(f"Accepted connection from {alice_address[0]}:{alice_address[1]}")

    # receive data from the client
    while True:
        request = alice_socket.recv(1024)
        request = request.decode("utf-8")  # convert bytes to string

        # if we receive "close" from the client, then we break
        # out of the loop and close the conneciton
        if request.lower() == "close":
            # send response to the client which acknowledges that the
            # connection should be closed and break out of the loop
            alice_socket.send("closed".encode("utf-8"))
            break

        print(f"Received: {request}")

        response = "accepted".encode("utf-8")  # convert string to bytes
        # convert and send accept response to the client
        alice_socket.send(response)

    # close connection socket with the client
    alice_socket.close()
    print("Connection to Alice closed")
    # close server socket
    listen_socket.close()


connect_alice()