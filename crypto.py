import os
import base64
import error_codes as error
from Crypto import Random
import binascii
from Crypto.Cipher import AES


def generate_random_bytes(size: int):
    return os.urandom(size)


class AESCipher:
    def __init__(self, key):
        self.key = key
        self.block_size = 16

    def encrypt_ecb(self, plaintext : bytes):
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(plaintext)

    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CBC, '\x00' * 16)
        return (cipher.encrypt(plaintext))

    def decrypt(self, ciphertext):
        enc = base64.b64decode(ciphertext)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[16:]))

    def _pad(self, s):
        return s + (self.block_size - len(s) % self.block_size) * chr(self.block_size - len(s) % self.block_size)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]
