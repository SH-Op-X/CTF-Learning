import struct
with open("judge.txt", "rb") as f:
    data = f.read()
c = []
for i in range(0, len(data), 4):
    c.append(struct.unpack("<I", data[i:i+4])[0])
total = c[-1]
for i in range(len(c)-2, -1, -1):
    c[i] ^= total
    total ^= c[i]
c = [0x7792d919] + c
print(len(c))
# print(c)


from ctypes import  c_uint8


def tea_encrypt(v):
    x0, x1, x2, x3, x4, x5 = c_uint8(v[0]), c_uint8(v[1]), c_uint8(v[2]), c_uint8(v[3]), c_uint8(v[4]), c_uint8(v[5])
    sum1 = c_uint8(0)
    sum2 = c_uint8(0)
    key = b"DBBBCA\x00"
    for i in range(64):
        sum1.value += 34
        sum2.value += 51
        x0.value += ((x1.value << 1) ^ (x1.value >> 4) ^ x1.value) ^ ((x2.value << 2) ^ (x2.value >> 5) ^ x2.value) ^ ((x3.value << 3) ^ (x3.value >> 6) ^ x3.value) ^ (
                    (x4.value << 4) ^ (x4.value >> 7) ^ x4.value) ^ ((x5.value << 5) ^ (x5.value >> 1) ^ x5.value) ^ (
                          sum1.value + sum2.value + key[(sum1.value & 3) + (sum2.value & 3)])
        sum1.value += 68
        x1.value += ((x2.value << 6) ^ (x2.value >> 2) ^ x2.value) ^ ((x3.value << 7) ^ (x3.value >> 3) ^ x3.value) ^ ((x4.value << 1) ^ (x4.value >> 4) ^ x4.value) ^ (
                    (x5.value << 2) ^ (x5.value >> 5) ^ x5.value) ^ ((x0.value << 3) ^ (x0.value >> 6) ^ x0.value) ^ (
                          sum1.value + sum2.value + key[(sum1.value & 3) + (sum2.value & 3)])
        sum1.value += 66
        sum2.value += 65
        x2.value += ((x3.value << 4) ^ (x3.value >> 7) ^ x3.value) ^ ((x4.value << 5) ^ (x4.value >> 1) ^ x4.value) ^ ((x5.value << 6) ^ (x5.value >> 2) ^ x5.value) ^ (
                    (x0.value << 7) ^ (x0.value >> 3) ^ x0.value) ^ ((x1.value << 1) ^ (x1.value >> 4) ^ x1.value) ^ (
                          sum1.value + sum2.value + key[(sum1.value & 3) + (sum2.value & 3)])
        sum1.value += 66
        sum2.value += 67
        x3.value += ((x4.value << 2) ^ (x4.value >> 5) ^ x4.value) ^ ((x5.value << 3) ^ (x5.value >> 6) ^ x5.value) ^ ((x0.value << 4) ^ (x0.value >> 7) ^ x0.value) ^ (
                    (x1.value << 5) ^ (x1.value >> 1) ^ x1.value) ^ ((x2.value << 6) ^ (x2.value >> 2) ^ x2.value) ^ (
                          sum1.value + sum2.value + key[(sum1.value & 3) + (sum2.value & 3)])
        sum1.value += 66
        sum2.value += 66
        x4.value += ((x5.value << 7) ^ (x5.value >> 3) ^ x5.value) ^ ((x0.value << 1) ^ (x0.value >> 4) ^ x0.value) ^ ((x1.value << 2) ^ (x1.value >> 5) ^ x1.value) ^ (
                    (x2.value << 3) ^ (x2.value >> 6) ^ x2.value) ^ ((x3.value << 4) ^ (x3.value >> 7) ^ x3.value) ^ (
                          sum1.value + sum2.value + key[(sum1.value & 3) + (sum2.value & 3)])
        sum1.value += 67
        sum2.value += 66
        x5.value += ((x0.value << 5) ^ (x0.value >> 1) ^ x0.value) ^ ((x1.value << 6) ^ (x1.value >> 2) ^ x1.value) ^ ((x2.value << 7) ^ (x2.value >> 3) ^ x2.value) ^ (
                    (x3.value << 1) ^ (x3.value >> 4) ^ x3.value) ^ ((x4.value << 2) ^ (x4.value >> 5) ^ x4.value) ^ (
                          sum1.value + sum2.value + key[(sum1.value & 3) + (sum2.value & 3)])
        sum1.value += 65
        sum2.value += 66
    return [x0.value, x1.value, x2.value, x3.value, x4.value, x5.value]


def tea_decrypt(v):
    x0, x1, x2, x3, x4, x5 = c_uint8(v[0]), c_uint8(v[1]), c_uint8(v[2]), c_uint8(v[3]), c_uint8(v[4]), c_uint8(v[5])
    sum1 = c_uint8((34+68+65+66+66+66+65)*64)
    sum2 = c_uint8((51+0+66+67+66+67+66)*64)
    key = b"DBBBCA\x00"
    for i in range(64):
        sum1.value -= 65
        sum2.value -= 66
        x5.value -= ((x0.value << 5) ^ (x0.value >> 1) ^ x0.value) ^ ((x1.value << 6) ^ (x1.value >> 2) ^ x1.value) ^ ((x2.value << 7) ^ (x2.value >> 3) ^ x2.value) ^ (
                    (x3.value << 1) ^ (x3.value >> 4) ^ x3.value) ^ ((x4.value << 2) ^ (x4.value >> 5) ^ x4.value) ^ (
                          sum1.value + sum2.value + key[(sum1.value & 3) + (sum2.value & 3)])
        sum1.value -= 67
        sum2.value -= 66
        x4.value -= ((x5.value << 7) ^ (x5.value >> 3) ^ x5.value) ^ ((x0.value << 1) ^ (x0.value >> 4) ^ x0.value) ^ ((x1.value << 2) ^ (x1.value >> 5) ^ x1.value) ^ (
                    (x2.value << 3) ^ (x2.value >> 6) ^ x2.value) ^ ((x3.value << 4) ^ (x3.value >> 7) ^ x3.value) ^ (
                          sum1.value + sum2.value + key[(sum1.value & 3) + (sum2.value & 3)])
        sum1.value -= 66
        sum2.value -= 66
        x3.value -= ((x4.value << 2) ^ (x4.value >> 5) ^ x4.value) ^ ((x5.value << 3) ^ (x5.value >> 6) ^ x5.value) ^ ((x0.value << 4) ^ (x0.value >> 7) ^ x0.value) ^ (
                    (x1.value << 5) ^ (x1.value >> 1) ^ x1.value) ^ ((x2.value << 6) ^ (x2.value >> 2) ^ x2.value) ^ (
                          sum1.value + sum2.value + key[(sum1.value & 3) + (sum2.value & 3)])
        sum1.value -= 66
        sum2.value -= 67
        x2.value -= ((x3.value << 4) ^ (x3.value >> 7) ^ x3.value) ^ ((x4.value << 5) ^ (x4.value >> 1) ^ x4.value) ^ ((x5.value << 6) ^ (x5.value >> 2) ^ x5.value) ^ (
                    (x0.value << 7) ^ (x0.value >> 3) ^ x0.value) ^ ((x1.value << 1) ^ (x1.value >> 4) ^ x1.value) ^ (
                          sum1.value + sum2.value + key[(sum1.value & 3) + (sum2.value & 3)])
        sum1.value -= 66
        sum2.value -= 65
        x1.value -= ((x2.value << 6) ^ (x2.value >> 2) ^ x2.value) ^ ((x3.value << 7) ^ (x3.value >> 3) ^ x3.value) ^ ((x4.value << 1) ^ (x4.value >> 4) ^ x4.value) ^ (
                    (x5.value << 2) ^ (x5.value >> 5) ^ x5.value) ^ ((x0.value << 3) ^ (x0.value >> 6) ^ x0.value) ^ (
                          sum1.value + sum2.value + key[(sum1.value & 3) + (sum2.value & 3)])
        sum1.value -= 68
        x0.value -= ((x1.value << 1) ^ (x1.value >> 4) ^ x1.value) ^ ((x2.value << 2) ^ (x2.value >> 5) ^ x2.value) ^ ((x3.value << 3) ^ (x3.value >> 6) ^ x3.value) ^ (
                    (x4.value << 4) ^ (x4.value >> 7) ^ x4.value) ^ ((x5.value << 5) ^ (x5.value >> 1) ^ x5.value) ^ (
                          sum1.value + sum2.value + key[(sum1.value & 3) + (sum2.value & 3)])
        sum1.value -= 34
        sum2.value -= 51
    return [x0.value, x1.value, x2.value, x3.value, x4.value, x5.value]


v = [0x57, 0xC2, 0x53, 0x0C, 0x05, 0x94, 0x6D, 0x47, 0xA5, 0x2E, 0xFA, 0x62, 0x1F, 0x96, 0x32, 0x26, 0xA3, 0x30, 0x30, 0x29, 0xD4, 0xA6, 0x86, 0x00, 0x0D, 0x52, 0x8D, 0x3B, 0xB9, 0xC3, 0x2C, 0x86, 0x19, 0xB5, 0x54, 0xA4]
for i in range(0, len(v), 6):
    v[i:i+6] = tea_decrypt(v[i:i+6])
print("".join(map(chr, v)))

