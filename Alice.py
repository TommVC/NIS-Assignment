import socket

def connect_bob():
    # create a socket object
    alice_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    bob_ip = "127.0.0.1"  # replace with the server's IP address
    bob_port = 8002  # replace with the server's port number
    # establish connection with server
    alice_send.connect((bob_ip, bob_port))

    while True:
        # input message and send it to the server
        msg = input("Enter message: ")
        alice_send.send(msg.encode("utf-8")[:1024])

        # receive message from the server
        response = alice_send.recv(1024)
        response = response.decode("utf-8")

        # if server sent us "closed" in the payload, we break out of the loop and close our socket
        if response.lower() == "closed":
            break

        print(f"Received: {response}")

    # close client socket (connection to the server)
    alice_send.close()
    print("Connection to Bob closed")


def run_alice():
    # create a socket object
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    alice_ip = "127.0.0.1"
    port = 8000

    # bind the socket to a specific address and port
    listen_socket.bind((alice_ip, port))
    # listen for incoming connections
    listen_socket.listen(0)
    print(f"Listening on {alice_ip}:{port}")

    # accept incoming connections
    bob_socket, bob_address = listen_socket.accept()
    print(f"Accepted connection from {bob_address[0]}:{bob_address[1]}")

    # receive data from the client
    while True:
        request = bob_socket.recv(1024)
        request = request.decode("utf-8")  # convert bytes to string

        # if we receive "close" from the client, then we break
        # out of the loop and close the conneciton
        if request.lower() == "close":
            # send response to the client which acknowledges that the
            # connection should be closed and break out of the loop
            bob_socket.send("closed".encode("utf-8"))
            break

        print(f"Received: {request}")

        response = "accepted".encode("utf-8")  # convert string to bytes
        # convert and send accept response to the client
        bob_socket.send(response)

    # close connection socket with the client
    bob_socket.close()
    print("Connection to Bob closed")
    # close server socket
    listen_socket.close()


run_alice()