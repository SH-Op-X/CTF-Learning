cmp = [8, 22, 33, 62, 8, 53, 40, 7, 8, 53, 16, 1, 5, 24, 25, 1, 5, 24, 64, 4, 40, 33, 64, 48, 52, 62, 30, 0x40, 0x71, 0x71]
flag = ""
for i in range(len(cmp)):
    flag += chr(cmp[i]^113)
print(flag)