import struct
from ctypes import c_uint32


def xtea_encrypt(r, v, key):
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    delta = 0x9e3779b9
    total = c_uint32(0)
    for i in range(r):
        v0.value += (((v1.value << 4) ^ (v1.value >> 5)) + v1.value) ^ (total.value + key[total.value & 3])
        total.value += delta
        v1.value += (((v0.value << 4) ^ (v0.value >> 5)) + v0.value) ^ (total.value + key[(total.value >> 11) & 3])
    return v0.value, v1.value


def xtea_decrypt(r, v, key):
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    delta = 0x12345678
    total = c_uint32(delta * r)
    for i in range(r):
        v1.value -= (((v0.value << 3) ^ (v0.value >> 5)) + v0.value) ^ (total.value + key[total.value + 1 & 3])
        total.value -= delta
        v0.value -= (((v1.value << 3) ^ (v1.value >> 5)) + v1.value) ^ (total.value + key[((total.value >> 11)+1) & 3])
    return v0.value, v1.value


if __name__ == "__main__":
    k = b"aaaassssddddffff"
    k = [struct.unpack("<I", k[i:i+4])[0] for i in range(0, 16, 4)]
    v = bytes.fromhex("f469358b7f165145116e127ad6105917bce5225d6d62a714c390c5ed93b22d8b6b102a8813488fdb")
    v = [struct.unpack(">I", v[i:i+4])[0] for i in range(0, len(v), 4)]
    for i in range(0, len(v), 2):
        v[i:i+2] = xtea_decrypt(16, v[i:i+2], k)
    str_list = []
    for i in range(len(v)):
        str_list += list(struct.pack('>I', v[i]))
    lst_ch = 0
    for i in range(len(str_list)):
        str_list[i] ^= lst_ch ^ (i + 1)
        lst_ch = str_list[i]
    print("".join(map(chr, str_list)))
