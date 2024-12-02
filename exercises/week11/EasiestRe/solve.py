c = [2, 3, 7, 14, 30, 57, 0x78, 251]
v = [977, 752, 82, 1141, 466, 752, 548, 1308, 1254, 671, 750, 923, 1017, 811, 754, 1461, 588, 1114, 844, 1389, 10, 1254, 1142, 729]
# for i in range(len(c)):
#     c[i] = 41 * c[i] % 0x1EB
inv = 12
c = c[::-1]
arr = []
for i in range(24):
    dec = v[i] * inv % 0x1eb
    ascii_char = 0
    for j in range(8):
        if dec >= c[j]:
            ascii_char += 2**j
            dec -= c[j]
    arr.append(ascii_char)
f = [4460]
f.extend(v)
flag = "".join(chr((arr[i]^f[i])%256) for i in range(24))
print(flag)
