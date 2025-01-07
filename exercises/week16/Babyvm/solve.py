#xor
from Crypto.Util.number import bytes_to_long

xor = [123, 47, 232, 55, 47, 232, 123, 55, 123, 123, 55, 55, 232, 47, 55, 123, 55, 55, 47, 123, 55, 123, 55, 232, 123, 232, 123, 55, 47, 55, 123, 47]
cmp = [74, 25, 221, 15, 27, 137, 25, 84, 79, 78, 85, 86, 142, 73, 14, 75, 6, 84, 26, 66, 83, 31, 82, 219, 25, 217, 25, 85, 25, 0, 75, 30]
flag = ""
for i in range(32):
    flag += chr(xor[i] ^ cmp[i])
print(flag)
s = [97] * 44

from itertools import product

s_list = list("0123456789abcdef")
for i in product(s_list, repeat=4):
    tmp = bytes_to_long("".join(i).encode())
    tmp = (tmp>>5)^tmp
    tmp = ((tmp<<7)&2565961507)^tmp
    tmp = ((tmp<<24)&904182048)^tmp
    if (tmp>>18)^tmp==0x6FEBF967:
        flag += ''.join(i)
        break
for i in product(s_list, repeat=4):
    tmp = bytes_to_long("".join(i).encode())
    reg1 = tmp
    reg3 = 32
    reg1 *= reg3
    reg1 &= 0xffffffff
    reg4 = reg1
    reg1 ^= tmp
    reg2 = 17
    reg1 >>= reg2
    reg5 = reg1
    reg1 = reg5
    reg1 ^= reg4
    reg1 ^= tmp
    reg2 = 13
    reg1 <<= reg2
    reg1 &= 0xffffffff
    reg1 ^= tmp
    reg1 ^= reg4
    reg1 ^= reg5
    tmp = reg1
    reg3 = 32
    reg1 *= reg3
    reg1 &= 0xffffffff
    reg4 = reg1
    reg1 ^= tmp
    reg2 = 17
    reg1 >>= reg2
    reg5 = reg1
    reg1 = reg5
    reg1 ^= reg4
    reg1 ^= tmp
    reg2 = 13
    reg1 <<= reg2
    reg1 &= 0xffffffff
    reg1 ^= tmp
    reg1 ^= reg4
    reg1 ^= reg5
    reg1 &= 0xffffffff
    if reg1 == 0xCF1304DC:
        flag += "".join(i)
        break
for i in product(s_list, repeat=4):
    tmp = bytes_to_long("".join(i).encode())
    reg1 = tmp
    reg3 = 32
    reg1 *= reg3
    reg1 &= 0xffffffff
    reg4 = reg1
    reg1 ^= tmp
    reg2 = 17
    reg1 >>= reg2
    reg5 = reg1
    reg1 = reg5
    reg1 ^= reg4
    reg1 ^= tmp
    reg2 = 13
    reg1 <<= reg2
    reg1 &= 0xffffffff
    reg1 ^= tmp
    reg1 ^= reg4
    reg1 ^= reg5
    tmp = reg1
    reg3 = 32
    reg1 *= reg3
    reg1 &= 0xffffffff
    reg4 = reg1
    reg1 ^= tmp
    reg2 = 17
    reg1 >>= reg2
    reg5 = reg1
    reg1 = reg5
    reg1 ^= reg4
    reg1 ^= tmp
    reg2 = 13
    reg1 <<= reg2
    reg1 &= 0xffffffff
    reg1 ^= tmp
    reg1 ^= reg4
    reg1 ^= reg5
    if reg1 == 0x283B8E84:
        flag += "".join(i)
        break
print(flag)