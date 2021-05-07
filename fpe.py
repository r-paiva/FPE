import config
import math
import crypto
import error_codes as error
from exceptions import InvalidConfigFile, InvalidRadixException
import log

ROUNDS = 10


def check_config_file():

    if config.AES_KEY_SIZE not in [16, 32]:
        raise InvalidConfigFile("Invalid Key Size.")

    if config.RADIX != 10:
        raise InvalidConfigFile("RADIX must be 10. (other values not yet tested)")

    if type(config.ENABLE_LOGGING) != bool:
        raise InvalidConfigFile("ENABLE LOGGING must be 'True' or 'False' ")

    return True


def isEven(n):
    return not ((n & 0x1) == 1)


"""
Input: Numeral String, X
Output: Number, x
"""
def num_radix(X):
    x = 0
    for i in X:
        x = x * config.RADIX + int(i)
    return x


def generate_p(split: int, n: int, t: int):
    P = [
        1,
        2,
        1,
        0, 0, config.RADIX,
        10,
        split,
        0, 0, 0, n,
        0, 0, 0, t
    ]

    return bytes(P)


def generate_q(T, i, B, b):
    Q = bytes(T.encode())
    Q += bytearray(-len(T) - b - 1 & 0x0F)
    Q += int(i).to_bytes(1, byteorder='big')
    Q += int(B).to_bytes(b, byteorder='big')

    return Q



# Prerequisites:
# Designated cipher function, CIPH, of an approved 128-bit block cipher;
# Key, K, for the block cipher
# Base, radix;
# Range of supported message lengths, [minlen ... maxlen];
# Maximum byte length for tweaks, maxTlen
# Inputs:
# Numeral string, X, in base radix of length n, such that n \in [minlen...maxlen]
# Tweak T, a byte string of byte length t, such that t \in [0...maxTlen]
# Output:
# Numeral string, Y, such that LEN(Y) = n
def encrypt(K: bytes, X, T):
    assert check_config_file()
    if not 2 <= config.RADIX <= 2**16:
        raise InvalidRadixException

    X = str(X)
    T = str(T)
    assert len(X) > 0, error.ErrorHandler.ERROR_EMPTY_MESSAGE
    n = len(X)
    t = len(T)
    u = math.floor(n / 2)
    v = n - u
    A = X[0:u]
    B = X[u:n]
    assert len(A) + len(B) == n, error.ErrorHandler.ERROR_FEISTEL_MESSAGE_LENGTH
    b = math.ceil(math.ceil(v * math.log(config.RADIX, 2)) / 8)
    d = 4 * int((b+3)/4)
    P = generate_p(u % 256, n, t)
    log.print_array(P, "P")
    bmagnitude = 10 ** int((n+1)/2)
    for i in range(0, ROUNDS):
        log.print_round(i)
        log.print_b(B)
        Q = generate_q(T, i, B, b)
        log.print_array(Q, "Q")

        to_encrypt = P + Q

        AES = crypto.AESCipher(K)
        R = AES.encrypt(to_encrypt)[-16:]
        log.print_array(R, "R")

        S = R[:d+4]
        y = int.from_bytes(S, byteorder='big')

        if isEven(i):
            m = u
        else:
            m = v

        c = (num_radix(A) + y) % (config.RADIX ** m)
        C = str(c)
        A = B
        B = C
        log.print_sides(A, B)

    return str(int(A) * bmagnitude + int(B))


def decrypt(K: bytes, X, T):
    assert check_config_file()
    if not 2 <= config.RADIX <= 2**16:
        raise InvalidRadixException

    X = str(X)
    T = str(T)
    assert len(X) > 0, error.ErrorHandler.ERROR_EMPTY_MESSAGE
    n = len(X)
    t = len(T)
    u = math.floor(n / 2)
    v = n - u
    A = X[0:u]
    B = X[u:n]
    assert len(A) + len(B) == n, error.ErrorHandler.ERROR_FEISTEL_MESSAGE_LENGTH
    b = math.ceil(math.ceil(v * math.log(config.RADIX, 2)) / 8)
    d = 4 * int((b+3)/4)
    P = generate_p(u % 256, n, t)
    log.print_array(P, "P")
    bmagnitude = 10 ** int((n+1)/2)
    for i in range(ROUNDS-1, -1, -1):
        log.print_round(i)
        log.print_b(B)
        Q = generate_q(T, i, A, b)
        log.print_array(Q, "Q")

        to_encrypt = P + Q

        AES = crypto.AESCipher(K)
        R = AES.encrypt(to_encrypt)[-16:]
        log.print_array(R, "R")

        S = R[:d+4]
        y = int.from_bytes(S, byteorder='big')

        if isEven(i):
            m = u
        else:
            m = v

        c = (num_radix(B) - y) % (config.RADIX ** m)
        C = str(c)
        B = A
        A = C
        log.print_sides(A, B)

    return str(int(A) * bmagnitude + int(B))




















