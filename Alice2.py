import socket
import threading
import time
from rsa_python import rsa

CONNECTED = False
def listen():
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = "127.0.0.1"
    port = 8002
    # bind the socket to a specific address and port
    listen_socket.bind((ip, port))
    # listen for incoming connections 
    listen_socket.listen(0)
    print(f"Listening on {ip}:{port}")
    client_socket, client_address = listen_socket.accept()
    msg = ""
    while not msg == "Q":
        msg = client_socket.recv(1024)
        msg = msg.decode("utf-8")
        if not(msg=="Q"):
            print("\n[Bob]:" + msg)
    return

def connect():
    while True:
        try:
            sendSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serverIP = "127.0.0.1"  # replace with the server's IP address
            serverPort = 8001  # replace with the server's port number
            # establish connection with server
            sendSocket.connect((serverIP, serverPort))
            print("Connected")
            verify_outgoing(sendSocket)  # Send public key to receiver
            print("finished being verified")
            break
        except:
            print("No one to connect to")
            time.sleep(5)

    msg = ""
#    while not msg == "Q":
#        msg = send(sendSocket)
#        time.sleep(1)
    return


def verify_outgoing(sskt):
    try:
        key_pair = rsa.generate_key_pair(1024)
        publicKey = key_pair["public"]
        privateKey = key_pair["private"]
        keyModulus = key_pair["modulus"]

        msg = "I am Alice"
        sskt.send(msg.encode("utf-8"))

        receive = sskt.recv(1024)
        nonce = receive.decode("utf-8")  # receive nonce
        print("Received nonce: " + nonce)

        encrypted_nonce = rsa.encrypt(nonce, privateKey, keyModulus)  # Encrypt with private key
        msg = encrypted_nonce
        sskt.send(msg.encode("utf-8"))  # send encrypted nonce
        print("Sent nonce: " + msg)
        time.sleep(2)
        msg = "END"
        sskt.send(msg.encode("utf-8"))  # specify end of encrypted nonce

        receive = sskt.recv(1024)
        receive = receive.decode("utf-8")  # receive request
        print("Received message: " + receive)

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
    msg = input("Send a message to Bob: ")
    skt.send(msg.encode("utf-8"))
    return msg

def main():
#    listenThread = threading.Thread(target=listen)
#    listenThread.start()
    connectThread = threading.Thread(target=connect)
    connectThread.start()

main()