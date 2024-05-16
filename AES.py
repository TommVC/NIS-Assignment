import base64
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome import Random

BLOCK_SIZE = 16

def pad(msg):
    if type(msg) == str:
        msg = (msg + (BLOCK_SIZE - len(msg) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(msg) % BLOCK_SIZE )).encode("utf-8")
    else:
        paddingByte = b'\x00'
        paddingLength = len(msg) + BLOCK_SIZE - len(msg) % BLOCK_SIZE
        msg = msg.ljust(paddingLength, paddingByte)
    return msg

def unpad(msg):
    if type(msg) == str:
        msg = msg[: -ord(msg[len(msg) - 1 :])]
    return msg

def encrypt(msg, key):
    private_key = hashlib.sha256(key.encode("utf-8")).digest()
    msg = pad(msg)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(msg))

def decrypt(msg, key):
    private_key = hashlib.sha256(key.encode("utf-8")).digest()
    msg = base64.b64decode(msg)
    iv = msg[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    msg = unpad(cipher.decrypt(msg[16:]))
    return msg