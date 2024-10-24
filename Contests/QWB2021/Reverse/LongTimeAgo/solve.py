import struct
from ctypes import c_uint32

def xtea_decrypt(r, v, key, delta):
    v0, v1 = c_uint32(v[0] ^ get_key(5)), c_uint32(v[1] ^ get_key(6))
    total = c_uint32(0xE6EF3D20)
    while total.value != 0:
        v1.value -= (((v0.value << 4) ^ (v0.value >> 5)) + v0.value) ^ (total.value + key[(total.value >> 11) & 3])
        total.value += delta
        v0.value -= (((v1.value << 4) ^ (v1.value >> 5)) + v1.value) ^ (total.value + key[total.value & 3])
    return v0.value, v1.value


def tea_decrypt(r, v, key, delta):
    v0, v1 = c_uint32(v[0] ^ get_key(7)), c_uint32(v[1] ^ get_key(8))
    total = c_uint32(delta * r)
    for i in range(r):
        v1.value -= ((v0.value << 4) + key[2]) ^ (v0.value + total.value) ^ ((v0.value >> 5) + key[3])
        v0.value -= ((v1.value << 4) + key[0]) ^ (v1.value + total.value) ^ ((v1.value >> 5) + key[1])
        total.value -= delta
    return v0.value, v1.value


def get_key(x):
    return (((1 << (x-1)) - 1) << 4)+13


if __name__ == "__main__":
    key = [get_key(i) for i in range(13, 17)]
    print(list(map(hex, key)))
    v = [0x1F306772, 0xB75B0C29, 0x4A7CDBE3, 0x2877BDDF, 0x1354C485, 0x357C3C3A, 0x738AF06C, 0x89B7F537]
    for i in range(0, 4, 2):
        v[i:i+2] = xtea_decrypt(32, v[i:i+2], key, 0x70C88617)
    for i in range(4, 8, 2):
        v[i:i+2] = tea_decrypt(32, v[i:i+2], key, 0x3d3529bc)
    flag = "QWB{"
    for i in v:
        flag += hex(i)[2:].zfill(8)
    print(flag+"}")
