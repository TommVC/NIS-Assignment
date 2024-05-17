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
PEER_KEY = b""
TESTFILE = open("./testing/ALICETEST.txt", "w")
diffieHellman = DiffieHellman()
cert = certificate()

privateKey = RSA.generate(3072)


def sendPK():  # Connect to CA server and send name + pk
    sendSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverIP = "127.0.0.1"  # replace with the server's IP address
    serverPort = 8003  # replace with the server's port number
    # establish connection with server
    sendSocket.connect((serverIP, serverPort))

    # send public key and modulus
    name = "Alice"
    sendSocket.send(name.encode("utf-8"))
    time.sleep(1)

    publicKey = privateKey.public_key().export_key()
    sendSocket.send(publicKey)
    TESTFILE.write("\nSENT NAME + PK: " + name + " " + str(publicKey) + "\n")

    # receive back certificate
    certif = sendSocket.recv(1024)
    cert.setCertificate(certif)

    signature = sendSocket.recv(1024)
    cert.setSignature(signature)
    TESTFILE.write("\nRECEIVED CERTIFICATE AND SIGNATURE: " + str(certif) + "\n" + str(signature) + "\n")

    receiveCa = sendSocket.recv(1024)
    caKey = RSA.import_key(receiveCa)
    cert.setCAKey(caKey)
    TESTFILE.write("\nRECEIVED CA PK: " + str(caKey) + "\n")


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
    peer_key = verifyIncoming(client_socket)  # Verifies incoming connection (is Alice actually Alice)
    global PEER_KEY
    PEER_KEY = peer_key
    global VERIFIED
    VERIFIED = True
    print("finished verification")

    #obtaining shared secret key
    secNum = client_socket.recv(1024)
    signature = client_socket.recv(1024)
    h = SHA256.new(secNum)
    verifier = pss.new(PEER_KEY)
    try:
        verifier.verify(h, signature)
        print("The signature of SECNUM is authentic.")
        TESTFILE.write("\nSIGNATURE OF SECNUM: AUTHENTIC" + "\n")
    except ValueError:
        print("The signature of SECNUM is not authentic.")
    secNum = eval(secNum.decode("utf-8"))
    TESTFILE.write("\nRECEIVED SECNUM: " + str(secNum) + "\n")
    diffieHellman.generateSecretKey(secNum)
    sharedKey = diffieHellman.getSecretKey()
    TESTFILE.write("\nSHARED KEY: " + str(sharedKey) + "\n")

    msg = ""
    while not msg == "Q":
        msg = receive(client_socket, sharedKey)
    return

def receive(skt, sharedKey):
    #receive file header data and decrypt
    fileHeader = skt.recv(1024).decode("utf-8")
    if fileHeader == "Q":
        return "Q"
    TESTFILE.write("\nRECEIVED HEADER ENCRYPTED: "+ fileHeader + "\n")
    fileHeader = AES.decrypt(fileHeader, str(sharedKey)).decode("utf-8")
    TESTFILE.write("\nRECEIVED HEADER DECRYPTED: "+ fileHeader + "\n")
    fileCaption, checksm = fileHeader.split("|")
    checksm = checksm[:len(hash.getCheckSum(fileCaption))] #unpad checksum
    #check hash
    if not(checksm == hash.getCheckSum(fileCaption)):
            print("Message Altered or Corrupted")
    elif fileCaption=="Q":
            return

    #split header data
    ifsize, fsize, fileCaption, fileChecksm = fileCaption.split("<>")
    imageFileName = fileCaption.replace(" ", "_") + "Alice"
    fsize = int(fsize)
    print("\nCaption:" + fileCaption)
    outfile = open("./output/" +imageFileName+".png", "wb")

    #receive encrypted file data
    data = skt.recv(1024)
    f = data
    fsize-=1024
    while fsize > 1024:
        data = skt.recv(1024)
        f+=data
        fsize-=1024
    data = skt.recv(fsize)
    f+=data
    #decrypt and unpad file data
    TESTFILE.write("\nRECEIVED FILE DATA ENCRYPTED: " + str(f) + "\n")
    f = AES.decrypt(f, str(sharedKey))
    TESTFILE.write("\nRECEIVED FILE DATA DECRYPTED: " + str(f) + "\n")
    f = f[:int(ifsize)]
    #check hash for file, if all good write bytes to output file
    if not(fileChecksm == hash.getCheckSum(f)):
        print("File altered or corrupted")
    else:
        TESTFILE.write("\nHASH: FILE NOT ALTERED IN TRANSIT\n")   
        outfile.write(f)

    return ""


def verifyIncoming(cskt):
    receivePeer = cskt.recv(1024)
    h = SHA256.new(receivePeer)
    caKey = cert.getCAKey()
    verifier = pss.new(caKey)
    receivePeer = receivePeer.decode("utf-8")

    name, peerKey = receivePeer.split("#")

    signature = cskt.recv(1024)


    try:
        verifier.verify(h, signature)
        print("The signature OF PK is authentic.")
    except ValueError:
        print("The signature OF PK is not authentic.")

    global PEER_KEY
    PEER_KEY = RSA.import_key(peerKey.encode("utf-8"))

    return PEER_KEY

def connect():
    triedConnection = False
    while True:
        try:
            sendSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serverIP = "127.0.0.1"  # replace with the server's IP address
            serverPort = 8001  # replace with the server's port number
            # establish connection with server
            sendSocket.connect((serverIP, serverPort))
            print("Connected")
            verify_outgoing(sendSocket)  # Send public key to receiver
            break
        except:
            if not triedConnection:
                print("No one to connect to")
                triedConnection = True
            time.sleep(2)

    while not VERIFIED:
        time.sleep(0.5)

    global PEER_KEY
    #send secret integer for diffie hellman
    secInt = diffieHellman.getSecretInteger()
    secInt = str(secInt)
    h = SHA256.new(secInt.encode("utf-8"))
    signature = pss.new(privateKey).sign(h)
    #print("SecInt:" + str(secInt))
    sendSocket.send(secInt.encode("utf-8"))
    time.sleep(1)
    sendSocket.send(signature)


    msg = ""
    while not msg == "Q":
        msg = sendMessage(sendSocket)
        time.sleep(1)
    return
            
def sendMessage(skt):
    sharedKey = diffieHellman.getSecretKey()
    msg=""
    if sharedKey:
        #open file for image wanting to be sent
        fileFound = False
        fileName = ""
        while (not fileFound) and not(fileName == "Q"):
            fileName = input("Enter file name of image you want to send (Q TO EXIT): ")
            try:
                file = open(fileName, "rb")
                fileFound = True
            except:
                print("No such file")
        if not fileName == "Q":
            fileData = file.read()
            TESTFILE.write("\nSENT FILE DATA: " + str(fileData) + "\n")
            ifsize = len(fileData) #initial file size before encryption, needed to unpad file after encryption
            #hash file and encrypt file data
            checksum = hash.getCheckSum(fileData)
            fileData = AES.encrypt(fileData, str(sharedKey))
            TESTFILE.write("\nSENT FILE DATA ENCRYPTED: " + str(fileData) + "\n")
            fsize = len(fileData) #length of encrypted file data, used for the receiver to know how much data they will receive
            #get file caption and send header data
            fileCaption = input("Enter the file caption: ")
            fileCaption = str(ifsize)+"<>"+str(fsize) + "<>" + fileCaption + "<>" + checksum
            TESTFILE.write("\nSENT FILE HEADER: " + fileCaption + "\n")
            fileCaption = AES.encrypt(hash.addHash(fileCaption), str(sharedKey)) #add checksum for header data and encrypt
            TESTFILE.write("\nSENT FILE HEADER ENCRYPTED: " + str(fileCaption) + "\n")
            skt.send(fileCaption)
            skt.sendall(fileData)
        else:
            msg = "Q"
            skt.send(fileName.encode("utf-8"))
    return msg


def verify_outgoing(sskt):
    msg = cert.getCertificate()
    signature = cert.getSignature()
    TESTFILE.write("\nSENT CERTIFICATE TO BOB: " + str(msg) + "\n" + str(signature) + "\n")
    sskt.send(msg)  # Send certificate
    time.sleep(1)
    sskt.send(signature)

def main():
    sendPK()
    listenThread = threading.Thread(target=listen)
    listenThread.start()
    connectThread = threading.Thread(target=connect)
    connectThread.start()


main()
