import struct

flag = ""
array1 = []
for i in [0x4FFED263, 0x3F00D9B9, 0x504380A0, 85]:
    array1 += list(struct.pack('<I', i))
s = [0xFD, 0x9A, 0x9F, 0xE8, 0xC2, 0xAE, 0x9B, 0x2D, 0xC3, 0x11, 0x2A, 0x35, 0xF6]
for i in range(13):
    if i % 3 == 0:
        flag += chr((array1[i]-s[i])&0xff)
    elif i % 3 == 1:
        flag += chr((array1[i]+s[i])&0xff)
    else:
        flag += chr(array1[i]^s[i])

maze = [0x54, 0x54, 0x54, 0x54, 0x54, 0x54, 0x3A, 0x30, 0x30, 0x30, 0x55, 0x3A, 0x54, 0x40, 0x54, 0x54, 0x54, 0x54, 0x3A, 0x30, 0x3A, 0x3A, 0x3A, 0x3A, 0x54, 0x40, 0x54, 0x54, 0x54, 0x54, 0x3A, 0x30, 0x30, 0x30, 0x30, 0x3A, 0x54, 0x54, 0x54, 0x54, 0x40, 0x54, 0x3A, 0x3A, 0x3A, 0x3A, 0x30, 0x3A, 0x54, 0x54, 0x54, 0x54, 0x88, 0x54, 0x3A, 0x3A, 0x3A, 0x3A, 0x3A, 0x3A]
new_maze = ""
for i in range(10):
    if i & 1:
        for j in range(6):
            new_maze += chr(maze[6*i+j]^0x10)
    else:
        for j in range(6):
            new_maze += chr(maze[6*i+j]>>1)
for i in range(10):
    print(new_maze[i*6:i*6+6])

step = "aaassssdddsss"
xor = []
for i in [0x41203E53, 0xB242C1E, 0x52372836, 14]:
    xor += list(struct.pack('<I', i))
for i in range(13):
    flag += chr(xor[i]^ord(step[i]))
print(flag)