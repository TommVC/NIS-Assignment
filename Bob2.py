import socket
import threading
import time
import base64
import hashlib
from Cryptodome.Cipher import AES
import DiffieHellman

diffieHellman = DiffieHellman.DiffieHellman()
#print("PrivInt:", diffieHellman.privNum)
sharedKey = None
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
            serverPort = 8002  # replace with the server's port number
            # establish connection with server
            sendSocket.connect((serverIP, serverPort))
            print("Connected")
            break
        except:
            print("No one to connect to")
            time.sleep(5)
    
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
    msg = input("Send a message to Bob: ")
    skt.send(msg.encode("utf-8"))
    return msg

def main():
    listenThread = threading.Thread(target=listen)
    listenThread.start()
    connectThread = threading.Thread(target=connect)
    connectThread.start()

main()