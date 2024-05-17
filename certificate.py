#this class just stores all the certificate data for a client

class certificate:

    def __init__(self):
        self.cert = None
        self.signature = None
        self.CAKey = None

    def getCAKey(self):
        return self.CAKey

    def setCAKey(self, key):
        self.CAKey = key

    def setCertificate(self, cert):
        self.cert = cert

    def getCertificate(self):
        return self.cert

    def setCertificate(self, cert):
        self.cert = cert

    def getSignature(self):
        return self.signature

    def setSignature(self, signature):
        self.signature = signature