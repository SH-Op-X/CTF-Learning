import struct
v = [0x7D2E370A180F1604, 0x3F7D132A2A252822, 0x392A7F3F39132D13, 0x31207C7C381320]
flag = []
for i in v:
    print(struct.pack("<q", i))
    flag += [j^0x4c for j in struct.pack("<q", i)]
print("".join(map(chr,flag)))