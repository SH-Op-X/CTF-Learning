import struct

with open("flag.txt", encoding="utf-8") as f:
    content = f.read()
data = content.split("\n")[3:]
float_data = []
for d in data:
    print(d.split()[1:7])
    float_data += d.split()[1:7]
for i in range(len(float_data)):
    float_data[i] = struct.unpack(">f", bytes.fromhex(float_data[i]))[0]
print(float_data)
flag = ""
for i in range(len(float_data)):
    if 32 < float_data[i] < 128:
        flag += chr(int(float_data[i]))
print(flag)