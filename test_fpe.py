import fpe as fpe
import crypto as crypto

for i in range(0, 100000):
    key_bytes = crypto.generate_random_bytes(16)
    input = int.from_bytes(crypto.generate_random_bytes(4), byteorder='big')
    tweak = int.from_bytes(crypto.generate_random_bytes(4), byteorder='big')
    cipher = fpe.encrypt(key_bytes, input, tweak)
    deciphered = fpe.decrypt(key_bytes, cipher, tweak)

