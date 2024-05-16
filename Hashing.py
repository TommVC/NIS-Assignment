import hashlib

def addHash(message):
    hashed = (message + '|' +hashlib.sha256(message.encode()).hexdigest())
    return hashed

def ogMsg (hashedMessage):
    ogMessage, hash = hashedMessage.split('|',1)
    return ogMessage, hash

def getCheckSum(message):
    if type(message) == str:
        message = message.encode()
    checksum = hashlib.sha256(message).hexdigest()
    return checksum