import struct
from ctypes import c_uint32


def tea_decrypt(r, v, key, delta):
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    total = c_uint32(-delta * r)
    for i in range(r):
        v1.value -= ((v0.value << 3) + key[2]) ^ (v0.value + total.value + 5) ^ ((v0.value >> 9) + key[3]) ^ 5
        v0.value -= ((v1.value << 3) + key[0]) ^ (v1.value + total.value + 5) ^ ((v1.value >> 9) + key[1]) ^ 5
        total.value += delta
    return v0.value, v1.value

def xtea_decrypt(r, v, key, delta):
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    total = c_uint32(0xC6EF3720-delta * r)
    for i in range(r):
        v1.value -= (((v0.value << 4) ^ (v0.value >> 3)) + v0.value) ^ (total.value + key[total.value & 4])
        v0.value -= (((v1.value << 4) ^ (v1.value >> 3)) + v1.value) ^ (total.value + key[(total.value >> 2) & 4])
        total.value += delta
    return v0.value, v1.value

v = [0x78156470, 0xA03F8FEA, 0x9A5483CA, 0xD609A639, 0x0F90345B, 0x12300B20, 0x38D00D6A, 0xC3F8C215, 0x842D02C9, 0x56CF1AFB]
delta = 0x61C88647
k = [0x00000021, 0x00000037, 0x0000004D, 0x00000063, 0]
for i in range(0, len(v), 2):
    v[i:i+2] = xtea_decrypt(32, v[i:i+2], k, delta)
print(list(map(hex, v)))
str_list = []
for i in range(len(v)):
    str_list.append(struct.pack('>I', v[i]).decode()[::-1])
print('decrypted: %s' % ''.join(str_list))#_Ant!+Debu9
