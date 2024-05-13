import socket
import threading
import time
from rsa_python import rsa

CONNECTED = False


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
#    verifyCA(name, alice_key)
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
    receive = receive.decode("utf-8")
    print("\n[Alice]: " + receive)  # Alice saying who they are

    nonce = "0.845312"
    msg = nonce
    cskt.send(msg.encode("utf-8"))  # send nonce to Alice
    print("sent nonce: " + nonce)

    encrypted_nonce = ""
    receive = cskt.recv(1024)
    receive = receive.decode("utf-8")  # receive encrypted nonce
    while receive != "END":
        encrypted_nonce = encrypted_nonce + receive
        receive = cskt.recv(1024)
        receive = receive.decode("utf-8")  # receive encrypted nonce
    print("Received encrypted nonce: " + encrypted_nonce)

    msg = "Send your public key"
    cskt.send(msg.encode("utf-8"))
    print("Message sent: " + msg)

    receive = cskt.recv(1024)
    alice_public = receive.decode("utf-8")  # receive Alice key modulus
    print("Public key received: " + alice_public)
    receive = cskt.recv(1024)
    alice_modulus = receive.decode("utf-8")  # receive Alice key modulus
    print("Public modulus received: " + alice_modulus)

    alice_modulus = int(alice_modulus)
    alice_public = int(alice_public)

    decrypted_nonce = rsa.decrypt(encrypted_nonce, alice_public, alice_modulus)
    print("Decrypted nonce: " + decrypted_nonce)

    if decrypted_nonce == nonce:
        print("Alice Confirmed")

    return alice_public, alice_modulus  # Return Alice public key to encrypt with


def connect():
    while True:
        try:
            sendSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serverIP = "127.0.0.1"  # replace with the server's IP address
            serverPort = 8002  # replace with the server's port number
            # establish connection with server
            sendSocket.connect((serverIP, serverPort))
            print("Connected")
            assymetricKeyGeneration()
            break
        except:
            print("No one to connect to")
            time.sleep(5)

    msg = ""
    while not msg == "Q":
        msg = send(sendSocket)
        time.sleep(1)
    return
            

def send(skt):
    msg = input("Send a message to Alice: ")
    skt.send(msg.encode("utf-8"))
    return msg


def assymetricKeyGeneration():
    key_pair = rsa.generate_key_pair(1024)
    publicKey = key_pair["public"]
    privateKey = key_pair["private"]
    keyModulus = key_pair["modulus"]

    cipher = rsa.encrypt("Hello World!", key_pair["private"], key_pair["modulus"])
    print(cipher)
    decrypted_message = rsa.decrypt(cipher, key_pair["public"], key_pair["modulus"])
    print(decrypted_message)


def main():
    listenThread = threading.Thread(target=listen)
    listenThread.start()
#    connectThread = threading.Thread(target=connect)
#    connectThread.start()


main()