import unittest
import fpe as FPE
import binascii
import crypto
import config
import exceptions


class TestVectors(unittest.TestCase):
    # test vectors from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt

    def test_vector1(self):
        key_bytes = binascii.unhexlify('2b7e151628aed2a6abf7158809cf4f3c')
        input = "0123456789"
        tweak = "9876543210"
        expected_result = "6124200773"
        self.assertEqual(expected_result, FPE.encrypt(key_bytes, input, tweak))

    def test_vector2(self):
        key_bytes = binascii.unhexlify('2b7e151628aed2a6abf7158809cf4f3c')
        input = "0123456789"
        tweak = ""
        expected_result = "2433477484"
        self.assertEqual(expected_result, FPE.encrypt(key_bytes, input, tweak))

    def test_vector3(self):
        key_bytes = binascii.unhexlify('2b7e151628aed2a6abf7158809cf4f3c')
        input = "314159"
        tweak = "2718281828"
        expected_result = "535005"
        self.assertEqual(expected_result, FPE.encrypt(key_bytes, input, tweak))

    def test_vector4(self):
        # this test was designed with 10 rounds.
        key_bytes = binascii.unhexlify('2b7e151628aed2a6abf7158809cf4f3c')
        input = "999999999"
        tweak = "7777777"
        expected_result = "658229573"
        self.assertEqual(expected_result, FPE.encrypt(key_bytes, input, tweak))


class TestConfigFile(unittest.TestCase):

    def test1(self):
        size = config.AES_KEY_SIZE
        config.AES_KEY_SIZE = 12
        self.assertRaises(exceptions.InvalidConfigFile, FPE.check_config_file)
        config.AES_KEY_SIZE = size

    def test2(self):
        radix = config.RADIX
        config.RADIX = 21
        self.assertRaises(exceptions.InvalidConfigFile, FPE.check_config_file)
        config.RADIX = radix

    def test3(self):
        logging = config.ENABLE_LOGGING
        config.ENABLE_LOGGING = "True"
        self.assertRaises(exceptions.InvalidConfigFile, FPE.check_config_file)
        config.ENABLE_LOGGING = logging


class TestDecryption(unittest.TestCase):

    def testfail(self):
        key_bytes = binascii.hexlify(b'GM\x7fB\x11\x80\xaf\x19\x9c\xbe]D5\x80M\x1f')
        input = "999999999"
        tweak = "7777777"

        self.assertEqual(
            input,
            FPE.decrypt(
                key_bytes,
                FPE.encrypt(
                    key_bytes,
                    input,
                    tweak),
                tweak
            )
        )

    def testDec1(self):
        key_bytes = crypto.generate_random_bytes(config.AES_KEY_SIZE)
        input = "999999999"
        tweak = "7777777"

        self.assertEqual(
            input,
            FPE.decrypt(
                key_bytes,
                FPE.encrypt(
                    key_bytes,
                    input,
                    tweak),
                tweak
            )
        )

    """def testFail2(self):
        for i in range(0, 10):
            key_bytes = bytes(b'7230231815ae76b69699626c7dac885f')
            print(key_bytes)
            input = str(int.from_bytes(bytes(crypto.generate_random_bytes(4)), byteorder='big'))
            tweak = str(int.from_bytes(bytes(crypto.generate_random_bytes(4)), byteorder='big'))
            ciphertext = FPE.encrypt(key_bytes, input, tweak)
            deciphered = FPE.decrypt(key_bytes, ciphertext, tweak)
            self.assertEqual(input, deciphered)
            print("testFail2 :")
            print("input ->", input)
            print("tweak ->", tweak)
            print("ciphertext -> ", ciphertext)
            print("deciphered -> ", deciphered)
            print(ciphertext)"""

    def testDec2_Random(self):

        key_bytes = crypto.generate_random_bytes(config.AES_KEY_SIZE)
        print(key_bytes)
        input = str(int.from_bytes(crypto.generate_random_bytes(2), byteorder='big'))
        tweak = str(int.from_bytes(crypto.generate_random_bytes(2), byteorder='big'))
        self.assertEqual(
            input,
            FPE.decrypt(
                key_bytes,
                FPE.encrypt(
                    key_bytes,
                    input,
                    tweak),
                tweak
            )
        )

if __name__ == '__main__':
    unittest.main()