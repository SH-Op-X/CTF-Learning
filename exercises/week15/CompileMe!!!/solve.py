import struct
from ctypes import c_uint64
import re

with open("Program.cs", "r", encoding="utf-8") as f:
    code = f.read()
results = re.findall("val ([\+-\^]) 0x(.*?);", code)


def decrypt(val):
    for i in range(len(results)):
        op = results[i][0]
        data = results[i][1]
        if op == "+":
            val += int(data, 16)
        elif op == "-":
            val -= int(data, 16)
        elif op == "^":
            val ^= int(data, 16)
    return val


def xtea_decrypt(r, v, key):
    v0, v1 = c_uint64(v[0]), c_uint64(v[1])
    delta = 0x9E3779B9
    total = c_uint64(delta * r)
    for i in range(r):
        v1.value -= (((v0.value << 4) ^ (v0.value >> 5)) + v0.value) ^ (total.value + key[(total.value >> 11) & 3])
        total.value -= delta
        v0.value -= (((v1.value << 4) ^ (v1.value >> 5)) + v1.value) ^ (total.value + key[total.value & 3])
    v0.value = decrypt(v0.value)
    v1.value = decrypt(v1.value)
    return v0.value, v1.value


if __name__ == "__main__":
    k = [0x57656c636f6d6520, 0x746f204e53534354, 0x4620526f756e6423, 0x3136204261736963]
    v = [0xc60b34b2bff9d34a, 0xf50af3aa8fd96c6b, 0x680ed11f0c05c4f1, 0x6e83b0a4aaf7c1a3, 0xd69b3d568695c3c5, 0xa88f4ff50a351da2, 0x5cfa195968e1bb5b, 0xc4168018d92196d9]
    for i in range(0, len(v), 2):
        v[i:i+2] = xtea_decrypt(32, v[i:i+2], k)
    str_list = []
    for i in range(len(v)):
        str_list.append(struct.pack('>q', v[i]).decode())
    print('decrypted: %s' % ''.join(str_list))#_Ant!+Debu9