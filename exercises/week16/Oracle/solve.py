def thirdPass(s):
    for i in range(42):
        s[i] -= ((7 * i * i) + (31 * i) + 127 + (i % 2))
        s[i] &= 0xff
    return s

def secondPass(s):
    f = [0] * 42
    for i in range(42):
        f[(i + 41) % 42] |= ((s[i] & 0xf0) >> 4)
        f[i] |= ((s[i] & 0xf) << 4)
    return f

def firstPass(s):
    for i in range(42):
        s[i] ^= (((((3 * i) * i) + (5 * i)) + 101) + (i % 2))
        s[i] &= 0xff
    return s

cmp = [48, 6, 122, -86, -73, -59, 78, 84, 105, -119, -36, -118, 70, 17, 101, -85, 55, -38, -91, 32, -18, -107, 53, 99, -74, 67, 89, 120, -41, 122, -100, -70, 34, -111, 21, -128, 78, 27, 123, -103, 36, 87]
print(len(cmp))
cmp = thirdPass(cmp)
cmp = secondPass(cmp)
cmp = firstPass(cmp)
print("".join(map(chr, cmp)))
