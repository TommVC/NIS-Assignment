#this class generates hashes for messages
import hashlib

#add hash for a message to the end of a message
def addHash(message):
    hashed = (message + '|' +hashlib.sha256(message.encode()).hexdigest())
    return hashed

#separate message and hash
def ogMsg (hashedMessage):
    ogMessage, hash = hashedMessage.split('|',1)
    return ogMessage, hash

#get hash for a message
def getCheckSum(message):
    if type(message) == str:
        message = message.encode()
    checksum = hashlib.sha256(message).hexdigest()
    return checksum