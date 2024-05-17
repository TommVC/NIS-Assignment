import secrets #secure random number generating library

#this class deals with all the Diffie Hellman shared key generation logic
class DiffieHellman:
    def __init__(self):
        self.publicModulus = 23 #first two fields are the public Diffie Hellman values
        self.publicBase = 6
        self.privNum = secrets.randbelow(100) #User's individual private number
        self.secretKey = None

    #generate the secret number to be sent to recipient for shared key generatiom
    def getSecretInteger(self):
        secInt = (self.publicBase ** self.privNum) % self.publicModulus
        return secInt

    #generate the secret shared key
    def generateSecretKey(self, num):
        self.secretKey = (num ** self.privNum) % self.publicModulus

    def getSecretKey(self):
        return self.secretKey
