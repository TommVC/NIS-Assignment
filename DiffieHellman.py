import secrets

class DiffieHellman:
    def __init__(self):
        self.publicModulus = 23
        self.publicBase = 6
        self.privNum = secrets.randbelow(100)
        self.secretKey = None

    def getSecretInteger(self):
        secInt = (self.publicBase ** self.privNum) % self.publicModulus
        return secInt

    def generateSecretKey(self, num):
        self.secretKey = (num ** self.privNum) % self.publicModulus

    def getSecretKey(self):
        return self.secretKey
