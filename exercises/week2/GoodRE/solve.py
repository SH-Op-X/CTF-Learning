from ctypes import c_uint32


def tea_decrypt(r, v, key, delta):
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    # delta = 0x9e3779b9
    total = c_uint32(delta * r)
    for i in range(r):
        v1.value -= ((v0.value << 4) + key[2]) ^ (v0.value + total.value) ^ ((v0.value >> 5) + key[3])
        v0.value -= ((v1.value << 4) + key[0]) ^ (v1.value + total.value) ^ ((v1.value >> 5) + key[1])
        total.value -= delta
    return v0.value, v1.value


if __name__ == '__main__':
    k = [17, 17, 17, 17]
    v = [0x79AE1A3B, 0x596080D3, 0x80E03E80, 0x846C8D73, 0x21A01CF7, 0xC7CACA32, 0x45F9AC14, 0xC5F5F22F]
    delta = 0x830A5376 ^ 0x1D3D2ACF
    for i in range(0, len(v), 2):
        v[i:i + 2] = tea_decrypt(32, v[i:i + 2], k, delta)
    flag = "flag{"
    for i in v:
        flag += hex(i)[2:].upper()
    flag += "}"
    print(flag)
