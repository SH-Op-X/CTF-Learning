import struct
from ctypes import c_uint32

v6 = [52, 15, 1, 14, 18]
Str2 = [-28, -25, -2, -29, 23, 28, -34, 50, -26, -72, 104, 64, 64, -40, 114, -6, -120, 20, -31, -123, -51, -127, -86, -34, 29, -24, -110, 65, -72, 30, 94, -49, -50, 73, 39, 34, 57, 125, 80, -38]
flag = ""


def xxtea_decrypt(n, v, key, delta):
    # 全部转为c_unit32格式
    v = [c_uint32(i) for i in v]
    r = 6 + 52 // n
    v0 = v[0].value
    total = c_uint32(delta * r)
    for i in range(r):
        e = (total.value >> 2) & 3
        for j in range(n-1, 0, -1):
            v1 = v[j-1].value
            v[j].value -= ((((v1 >> 5) ^ (v0 << 2)) + ((v0 >> 3) ^ (v1 << 4))) ^ ((total.value ^ v0) + (key[(j & 3) ^ e] ^ v1)))
            v0 = v[j].value
        v1 = v[n-1].value
        v[0].value -= ((((v1 >> 5) ^ (v0 << 2)) + ((v0 >> 3) ^ (v1 << 4))) ^ ((total.value ^ v0) + (key[(0 & 3) ^ e] ^ v1)))
        v0 = v[0].value
        total.value -= delta
    return [i.value for i in v]

v = Str2
k = list(b"He1l0NsS!")+[0x11, 0x45, 0x14, 0x19, 0x19, 0x81, 0]
k = [int.from_bytes(k[i:i+4], byteorder="little") for i in range(0, 16, 4)]
# print(list(map(hex, k)))
v = [i&0xff for i in v]
v = [int.from_bytes(v[i:i+4], byteorder="little") for i in range(0, len(v), 4)]
v = xxtea_decrypt(len(v), v, k, 0x11451981)
# 输出解密后的数据
str_list = []
for i in range(len(v)):
    str_list.append(struct.pack('>I', v[i]).decode()[::-1])
print('decrypted: %s' % ''.join(str_list))