def enc1(word, i):
    word = ord(word) ^ 0x76 ^ 0xAD
    temp1 = (word & 0xAA) >> 1
    temp2 = 2 * word & 0xAA
    word = temp1 | temp2
    return word


def enc2(word, i):
    word = ord(word) ^ 0x76 ^ 0xBE
    temp1 = (word & 0xCC) >> 2
    temp2 = 4 * word & 0xCC
    word = temp1 | temp2
    return word


def enc3(word, i):
    word = ord(word) ^ 0x76 ^ 0xEF
    temp1 = (word & 0xF0) >> 4
    temp2 = 16 * word & 0xF0
    word = temp1 | temp2
    return word

f = open('output','rb')
output = f.read()
flag = ""
for i in range(5):
    for j in range(32, 127):
        if enc1(chr(j), i) == output[i]:
            flag += chr(j)
            break
for i in range(5):
    for j in range(32, 127):
        if enc2(chr(j), i) == output[i+5]:
            flag += chr(j)
            break
for i in range(5):
    for j in range(32, 127):
        if enc3(chr(j), i) == output[i+10]:
            flag += chr(j)
            break
print(flag)
