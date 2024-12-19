s = [0x69, 0x45, 0x2A, 0x37, 0x09, 0x17, 0xC5, 0x0B, 0x5C, 0x72, 0x33, 0x76, 0x33, 0x21, 0x74, 0x31, 0x5F, 0x33, 0x73, 0x72]
print(len(s))
# s[0] ^= s[1]
# s[1] ^= s[2]
# s[2] ^= s[3]
# s[3] ^= s[4]
# s[4] ^= s[5]
# s[5] ^= s[6]
# s[6] = (3*s[6]+2*s[7]+s[8])*s[12]&0xff
# s[7] = (3*s[7]+2*s[8]+s[9])*s[12]&0xff
# s[8] = (3*s[8]+2*s[9]+s[10])*s[12]&0xff
s[13], s[19] = s[19], s[13]
s[14], s[18] = s[18], s[14]
s[15], s[17] = s[17], s[15]
for i in range(32, 127):
    if (3*i+2*s[9]+s[10])*s[12]&0xff == s[8]:
        s[8] = i
        break
for i in range(32, 127):
    if (3*i+2*s[8]+s[9])*s[12]&0xff == s[7]:
        s[7] = i
        break
for i in range(32, 127):
    if (3 * i + 2 * s[7] + s[8]) * s[12] & 0xff == s[6]:
        s[6] = i
        break
for i in range(5, -1, -1):
    s[i] ^= s[i+1]
print("".join(map(chr, s)))
