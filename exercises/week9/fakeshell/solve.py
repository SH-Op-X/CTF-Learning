cmp = [0x0000004B, 0x00000048, 0x00000079, 0x00000013, 0x00000045, 0x00000030, 0x0000005C, 0x00000049, 0x0000005A, 0x00000079, 0x00000013, 0x00000070, 0x0000006D, 0x00000078, 0x00000013, 0x0000006F, 0x00000048, 0x0000005D, 0x00000064, 0x00000064]
flag = ""
for i in range(len(cmp)):
    flag += chr((cmp[i]^0x50)-10^0x66)
print(flag)