import base64
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome import Random

BLOCK_SIZE = 16

def pad(msg):
    return msg + (BLOCK_SIZE - len(msg) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(msg) % BLOCK_SIZE )

def unpad(msg):
    return msg[: -ord(msg[len(msg) - 1 :])]

def encrypt(msg, key):
    private_key = hashlib.sha256(key.encode("utf-8")).digest()
    msg = pad(msg).encode("utf-8")
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(msg))

def decrypt(msg, key):
    private_key = hashlib.sha256(key.encode("utf-8")).digest()
    msg = base64.b64decode(msg)
    iv = msg[:16]
    print(len(iv))
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(msg[16:]))