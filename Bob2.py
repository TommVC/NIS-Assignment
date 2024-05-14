import socket
import threading
import time
from rsa_python import rsa

CONNECTED = False
VERIFIED = False  # Makes sure messages can only be sent to receiver once receiver is verified
key_pair = rsa.generate_key_pair(1024)  # Generates public key immediately
CERTIFICATE = ""
CA_KEY = ""
CA_MODULUS = ""


def sendPK():  # Connect to CA server and send name + pk
    sendSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverIP = "127.0.0.1"  # replace with the server's IP address
    serverPort = 8003  # replace with the server's port number
    # establish connection with server
    sendSocket.connect((serverIP, serverPort))
    print("Connected")

    # send public key and modulus
    name = "Bob"
    sendSocket.send(name.encode("utf-8"))
#    print("sent name")
    time.sleep(2)
    public_key = str(key_pair["public"])
    sendSocket.send(public_key.encode("utf-8"))
#    print("sent public key")
    time.sleep(2)
    modulus_key = str(key_pair["modulus"])
    sendSocket.send(modulus_key.encode("utf-8"))
#    print("sent public modulus")

    # receive back certificate

    msg = sendSocket.recv(1024)
    msg = msg.decode("utf-8")
    global CERTIFICATE
    while msg != "END":
        CERTIFICATE = CERTIFICATE + msg
        msg = sendSocket.recv(1024)
        msg = msg.decode("utf-8")
#    print("Encrypted certificate: " + CERTIFICATE)


    # receive CA public key
    msg = sendSocket.recv(1024)
    msg = msg.decode("utf-8")
    msg = msg.split('#')
    global CA_KEY
    CA_KEY = msg[0]
    CA_KEY = int(CA_KEY)
#    print(CA_KEY)
    global CA_MODULUS
    CA_MODULUS = msg[1]
    CA_MODULUS = int(CA_MODULUS)
#    print(CA_MODULUS)

#    CA_KEY = int(CA_KEY)
#    CA_MODULUS = int(CA_MODULUS)

#    CERTIFICATE = rsa.decrypt(CERTIFICATE, CA_KEY, CA_MODULUS)
#    print("Decrypted certificate: " + CERTIFICATE)


def listen():  # Incoming messages
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = "127.0.0.1"
    port = 8001
    # bind the socket to a specific address and port
    listen_socket.bind((ip, port))
    # listen for incoming connections 
    listen_socket.listen(0)
    print(f"Listening on {ip}:{port}")
    client_socket, client_address = listen_socket.accept()
    name, alice_key = verifyIncoming(client_socket)  # Verifies incoming connection (is Alice actually Alice)
    global VERIFIED
    VERIFIED = True
    print("finished verification")
    msg = ""
    while not msg == "Q":
        msg = client_socket.recv(1024)
        msg = msg.decode("utf-8")
        if not(msg=="Q"):
            print("\n[Alice]:" + msg)
    return


def verifyIncoming(cskt):
    receive = cskt.recv(1024)
    name = receive.decode("utf-8")
    print("\n[Alice]: " + name)  # Alice saying who they are

    nonce = "0.845312"
    msg = nonce
    cskt.send(msg.encode("utf-8"))  # send nonce to Alice
#    print("sent nonce: " + nonce)

    encrypted_nonce = ""
    receive = cskt.recv(1024)
    receive = receive.decode("utf-8")  # receive encrypted nonce
    while receive != "END":
        encrypted_nonce = encrypted_nonce + receive
        receive = cskt.recv(1024)
        receive = receive.decode("utf-8")  # receive encrypted nonce
#    print("Received encrypted nonce: " + encrypted_nonce)

    msg = "Send your public key"
    cskt.send(msg.encode("utf-8"))
    #    print("Message sent: " + msg)

#    receive = cskt.recv(1024)
#    clientCert = receive.decode("utf-8")

#    clientCert = rsa.decrypt(clientCert, CA_KEY, CA_MODULUS)  # decrypt cert
#    print(clientCert)


    receive = cskt.recv(1024)
    bob_public = receive.decode("utf-8")  # receive Alice key modulus
    print("Public key received: " + bob_public)
    receive = cskt.recv(1024)
    bob_modulus = receive.decode("utf-8")  # receive Alice key modulus
    print("Public modulus received: " + bob_modulus)

    bob_modulus = int(bob_modulus)
    bob_public = int(bob_public)

    decrypted_nonce = rsa.decrypt(encrypted_nonce, bob_public, bob_modulus)
    print("Decrypted nonce: " + decrypted_nonce)

    if decrypted_nonce == nonce:
        print("Bob Confirmed")

    return name, bob_public  # Return Alice public key to encrypt with


def connect():
    while True:
        try:
            sendSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serverIP = "127.0.0.1"  # replace with the server's IP address
            serverPort = 8002  # replace with the server's port number
            # establish connection with server
            sendSocket.connect((serverIP, serverPort))
            print("Connected")
            verify_outgoing(sendSocket)  # Send public key to receiver
            print("finished being verified")
            break
        except:
            print("No one to connect to")
            time.sleep(5)

    while not VERIFIED:
        time.sleep(1)

    msg = ""
    while not msg == "Q":
        msg = send(sendSocket)
        time.sleep(1)
    return


def verify_outgoing(sskt):
    try:
        publicKey = key_pair["public"]
        privateKey = key_pair["private"]
        keyModulus = key_pair["modulus"]

        msg = "Bob"
        sskt.send(msg.encode("utf-8"))

        receive = sskt.recv(1024)
        nonce = receive.decode("utf-8")  # receive nonce
#        print("Received nonce: " + nonce)

        encrypted_nonce = rsa.encrypt(nonce, privateKey, keyModulus)  # Encrypt with private key
        msg = encrypted_nonce
        sskt.send(msg.encode("utf-8"))  # send encrypted nonce
#        print("Sent nonce: " + msg)
        time.sleep(2)
        msg = "END"
        sskt.send(msg.encode("utf-8"))  # specify end of encrypted nonce

        receive = sskt.recv(1024)
        receive = receive.decode("utf-8")  # receive request
#        print("Received message: " + receive)

#        msg = CERTIFICATE
#        sskt.send(msg.encode("utf-8"))  # Send certificate

        publicKey = str(publicKey)  # Only strings can be encoded
        keyModulus = str(keyModulus)

        msg = publicKey
        sskt.send(msg.encode("utf-8"))  # send public key
        print("Public key sent: " + msg)
        time.sleep(2)  # So they are in two different messages
        msg = keyModulus
        sskt.send(msg.encode("utf-8"))  # send key modulus
        print("Public modulus sent: " + msg)

    except Exception as e:
        print(e)

    return


def send(skt):
    msg = input("Send a message to Alice: ")
    skt.send(msg.encode("utf-8"))
    return msg


def main():
#    sendPK()
    listenThread = threading.Thread(target=listen)
    listenThread.start()
    connectThread = threading.Thread(target=connect)
    connectThread.start()


main()