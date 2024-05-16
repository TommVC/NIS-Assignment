import socket
import os
import threading
import time
import random
from rsa_python import rsa
from DiffieHellman import *
import AES
import Hashing as hash

CONNECTED = False
VERIFIED = False  # Makes sure messages can only be sent to receiver once receiver is verified
key_pair = rsa.generate_key_pair(1024)  # Generates public key immediately
CERTIFICATE = ""
CA_KEY = ""
CA_MODULUS = ""
PEER_KEY = ""
PEER_MODULUS = ""

diffieHellman = DiffieHellman()
#print("PrivInt:", diffieHellman.privNum)

def sendPK():  # Connect to CA server and send name + pk
    sendSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverIP = "127.0.0.1"  # replace with the server's IP address
    serverPort = 8003  # replace with the server's port number
    # establish connection with server
    sendSocket.connect((serverIP, serverPort))
    print("Connected to CA\nReceiving certificate...")

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
    alice_key, alice_modulus = verifyIncoming(client_socket)  # Verifies incoming connection (is Alice actually Alice)
    global PEER_KEY
    PEER_KEY = alice_key
    global PEER_MODULUS
    PEER_MODULUS = alice_modulus
    global VERIFIED
    VERIFIED = True
    print("finished verification")

    #obtaining shared secret key
    secNum = client_socket.recv(1024).decode("utf-8")
    secNum = eval(rsa.decrypt(secNum, PEER_KEY, PEER_MODULUS))
    #print("SecNum:" + str(secNum))
    diffieHellman.generateSecretKey(secNum)
    sharedKey = diffieHellman.getSecretKey()
    #print("SK:" + str(sharedKey))
    print("Shared Key generated")

    msg = ""
    while not msg == "Q":
        receive(client_socket, sharedKey)
    return

def receive(skt, sharedKey):
    fileCaption = skt.recv(1024).decode("utf-8")
    fileCaption = AES.decrypt(fileCaption, str(sharedKey)).decode("utf-8")
    fileCaption, checksm = fileCaption.split("|")
    checksm = checksm[:len(hash.getCheckSum(fileCaption))]
    if not(checksm == hash.getCheckSum(fileCaption)):
            print("Message Altered or Corrupted")
    elif fileCaption=="Q":
            return
    ifsize, fsize, fileCaption, fileChecksm = fileCaption.split("<>")
    fsize = int(fsize)
    print("\nCaption:" + fileCaption)
    outfile = open("output/output.png", "wb")
    data = skt.recv(1024)
    f = data
    fsize-=1024
    while fsize > 1024:
        data = skt.recv(1024)
        f+=data
        fsize-=1024
    data = skt.recv(fsize)
    f+=data
    f = AES.decrypt(f, str(sharedKey))
    f = f[:int(ifsize)]
    if not(fileChecksm == hash.getCheckSum(f)):
        print("File altered or corrupted")
    else:
        outfile.write(f)


def verifyIncoming(cskt):
    receive = cskt.recv(1024)
    name = receive.decode("utf-8")
#    print("\n[Alice]: " + name)  # Alice saying who they are

    nonce = str(random.uniform(0, 1))
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

    clientCert = ""
    receive = cskt.recv(1024)
    receive = receive.decode("utf-8")
    while receive != "END":
        clientCert = clientCert + receive
        receive = cskt.recv(1024)
        receive = receive.decode("utf-8")  # receive encrypted nonce

    clientCert = rsa.decrypt(clientCert, CA_KEY, CA_MODULUS)  # decrypt cert
#    print(clientCert)

    clientCert = clientCert.split('#')
    cert_name = clientCert[0]
    alice_key = clientCert[1]
    alice_modulus = clientCert[2]

    if cert_name == name:
        print("Alice name confirmed")
        alice_modulus = int(alice_modulus)
        alice_key = int(alice_key)
        decrypted_nonce = rsa.decrypt(encrypted_nonce, alice_key, alice_modulus)
        print("Decrypted nonce: " + decrypted_nonce)
        if decrypted_nonce == nonce:
            print("Alice identity confirmed")
        else:
            print("Security breach")
    else:
        print("security breach")

    return alice_key, alice_modulus


def connect():
    triedConnection = False
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
            if not triedConnection:
                print("No one to connect to")
                triedConnection = True
            time.sleep(2)

    while not VERIFIED:
        time.sleep(1)

    #send secret integer for diffie hellman
    secInt = diffieHellman.getSecretInteger()
    secInt = rsa.encrypt(str(secInt), key_pair["private"], key_pair["modulus"])
    #print("SecInt:" + str(secInt))
    sendSocket.send(secInt.encode("utf-8"))

    msg = ""
    while not msg == "Q":
        msg = sendMessage(sendSocket)
        time.sleep(1)
    return
            
def sendMessage(skt):
    sharedKey = diffieHellman.getSecretKey()
    msg=""
    if sharedKey:
        fileName = input("Enter file name of image you want to send: ")
        file = open(fileName, "rb")
        fileData = file.read()
        ifsize = len(fileData)
        checksum = hash.getCheckSum(fileData)
        fileData = AES.encrypt(fileData, str(sharedKey))
        fsize = len(fileData)
        fileCaption = input("Enter the file caption: ")
        fileCaption = str(ifsize)+"<>"+str(fsize) + "<>" + fileCaption + "<>" + checksum
        print(fileCaption +" " +hash.getCheckSum(fileCaption))
        fileCaption = AES.encrypt(hash.addHash(fileCaption), str(sharedKey))
        skt.send(fileCaption)
        skt.sendall(fileData)
    return msg

def verify_outgoing(sskt):
    try:
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

        msg = CERTIFICATE
        sskt.send(msg.encode("utf-8"))  # Send certificate
        time.sleep(1)
        sskt.send("END".encode("utf-8"))


    except Exception as e:
        print(e)

    return


def main():
    sendPK()
    listenThread = threading.Thread(target=listen)
    listenThread.start()
    connectThread = threading.Thread(target=connect)
    connectThread.start()


main()