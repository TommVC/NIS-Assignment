import socket
import os
import threading
import time
from DiffieHellman import *
import AES
import Hashing as hash

diffieHellman = DiffieHellman()
#print("PrivInt:", diffieHellman.privNum)
def listen():
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = "127.0.0.1"
    port = 8001
    # bind the socket to a specific address and port
    listen_socket.bind((ip, port))
    # listen for incoming connections 
    listen_socket.listen(0)
    print(f"Listening on {ip}:{port}")
    client_socket, client_address = listen_socket.accept()

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
    outfile = open("./output/output.png", "wb")
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
            break
        except:
            if not triedConnection:
                print("No one to connect to")
                triedConnection = True
            time.sleep(2)
    
    #send secret integer for diffie hellman
    secInt = diffieHellman.getSecretInteger()
    #print("SecInt:" + str(secInt))
    sendSocket.send(str(secInt).encode("utf-8"))

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

def main():
    listenThread = threading.Thread(target=listen)
    listenThread.start()
    connectThread = threading.Thread(target=connect)
    connectThread.start()

main()