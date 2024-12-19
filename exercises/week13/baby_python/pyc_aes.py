# Visit https://www.lddgo.net/string/pyc-compile-decompile for more information
# Python 3.7.0 (3394)

import sys
import zlib

CRYPT_BLOCK_SIZE = 16


class Cipher(object):
    __doc__ = "\n    This class is used only to decrypt Python modules.\n    "

    def __init__(self):
        key = "f8c0870eba862579"
        if not type(key) is str:
            raise AssertionError
        elif len(key) > CRYPT_BLOCK_SIZE:
            self.key = key[:CRYPT_BLOCK_SIZE]
        else:
            self.key = key.zfill(CRYPT_BLOCK_SIZE)
        assert len(self.key) == CRYPT_BLOCK_SIZE
        import tinyaes
        self._aesmod = tinyaes
        del sys.modules["tinyaes"]

    def __create_cipher(self, iv):
        return self._aesmod.AES(self.key.encode(), iv)

    def decrypt(self, data):
        cipher = self.__create_cipher(data[:CRYPT_BLOCK_SIZE])
        return cipher.CTR_xcrypt_buffer(data[CRYPT_BLOCK_SIZE:])


from Crypto.Cipher import AES
c = Cipher()
with open("baby_core.pyc.encrypted", "rb") as f:
    data = f.read()

buffer = b'\x42\x0D\x0D\x0A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
buffer += zlib.decompress(c.decrypt(data))
with open("baby_core.pyc", "wb") as f1:
    f1.write(buffer)

