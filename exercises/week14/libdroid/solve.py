ss = [[16, 244, 82, 178, 31, 249, 85, 250, 19, 252], [17, 247, 93, 182, 26, 255, 25, 255, 28, 247, 12, 233], [48, 244, 82, 179, 4, 255, 15, 230, 17, 244], [83, 170, 14, 231, 66, 171, 77, 164, 69, 172, 80], [24, 254, 69, 233], [1, 244, 83, 160, 29, 247, 15, 174], [32, 244, 78, 166, 15, 190, 21, 252, 93, 231, 15, 231, 2, 245, 25, 236, 91, 245, 17, 228, 28, 173, 15, 253, 71, 181, 82]]
for s in ss:
    key = b"c<clinit>tf.stratumauhhur.libdroid.a"
    k = len(key)
    for i in range(0, len(s), 2):
        s[i] ^= 18 ^ key[k-1]
        if i + 1 == len(s):
            break
        s[i+1] ^= 0xfa ^ key[k-1]
        k -= 1
        if k == 0:
            k = len(key)
    print("".join(map(chr, s)))

key = b"blablablabla"
with open("config.ini", "rb") as f:
    data = list(f.read())
for i in range(len(data)):
    data[i] ^= key[i%len(key)]
print("".join(map(chr,data)))

from base64 import b64decode
import struct
from ctypes import c_uint32
from itertools import product


def tea_decrypt(v, key, delta):
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    total = c_uint32(0xD5B7DDE0)
    while True:
        v1.value -= ((v0.value << 4) + key[2]) ^ (v0.value + total.value) ^ ((v0.value >> 5) + key[3])
        v0.value -= ((v1.value << 4) + key[0]) ^ (v1.value + total.value) ^ ((v1.value >> 5) + key[1])
        total.value += delta
        if total.value == 0:
            break
    return v0.value, v1.value


with open("c", "rb") as f:
    data = list(f.read())
for i in product([32]+list(range(49, 58)), repeat=6):
    v = [struct.unpack("<I", bytes(data[i:i+4]))[0] for i in range(0, len(data), 4)]
    key = list(b64decode(b"IQCGt/+GXQYtMA==")) + list(i)
    key = [struct.unpack("<I", bytes(key[i:i+4]))[0] for i in range(0, len(key), 4)]
    delta = 0x21524111
    for i in range(0, len(v), 2):
        v[i:i+2] = tea_decrypt(v[i:i+2], key, delta)
    str_list = []
    try:
        for i in range(len(v)):
            str_list.append(struct.pack('<I', v[i]).decode())
        print('decrypted: %s' % ''.join(str_list))
        break
    except:
        continue