import socket
import os
import threading
import time
import random
from DiffieHellman import *
from certificate import *
import AES
import Hashing as hash
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256


CONNECTED = False
VERIFIED = False  # Makes sure messages can only be sent to receiver once receiver is verified
CERTIFICATE = ""
CA_KEY = ""
PEER_KEY = ""

diffieHellman = DiffieHellman()
cert = certificate()


privateKey = RSA.generate(3072)


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
    time.sleep(1)

    publicKey = privateKey.public_key().export_key()
    sendSocket.send(publicKey)
    print("sent public key: " + str(publicKey))

    # receive back certificate
    certif = sendSocket.recv(1024)
    cert.setCertificate(certif)
    print("Signed certificate: " + str(cert))
    signature = sendSocket.recv(1024)
    print("Signature: " + str(signature))

    receiveCa = sendSocket.recv(1024)
    print("CA Key: " + str(receiveCa))
    caKey = RSA.import_key(receiveCa)
    print("CA Key: " + str(caKey))

    # message = cert
    #
    # h = SHA256.new(message)
    # verifier = pss.new(caKey)
    # try:
    #     verifier.verify(h, signature)
    #     print("The signature is authentic.")
    # except ValueError:
    #     print("The signature is not authentic.")


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
    peer_key = verifyIncoming(client_socket)  # Verifies incoming connection (is Alice actually Alice)
    global PEER_KEY
    PEER_KEY = peer_key
    global VERIFIED
    VERIFIED = True
    print("finished verification")

    #obtaining shared secret key
    secNum = eval(client_socket.recv(1024).decode("utf-8"))
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
    receivePeer = cskt.recv(1024)
    receivePeer = receivePeer.decode("utf-8")
    print("Received peer: " + receivePeer)
    receivePeer = receivePeer.split("#")

    name = receivePeer[0]
    peerKey = receivePeer[1].encode("utf-8")
    global PEER_KEY
    print("Key attempt: ")
    print(peerKey)
    PEER_KEY = RSA.import_key(peerKey)
    print("Peer Key: " + str(PEER_KEY))

    return PEER_KEY


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
    msg = cert.getCertificate()
    print("Sending cert: " + msg)
    sskt.send(msg)  # Send certificate



def main():
    sendPK()
    listenThread = threading.Thread(target=listen)
    listenThread.start()
    connectThread = threading.Thread(target=connect)
    connectThread.start()


main()