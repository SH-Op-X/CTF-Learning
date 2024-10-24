from Crypto.Cipher import AES

s = [66,
     114,
     97,
     105,
     110,
     115,
     116,
     111,
     114,
     109,
     105,
     110,
     103,
     33,
     33,
     33]
s = "".join(map(chr, s))
print(s)
aes = AES.new(s.encode(), AES.MODE_ECB)
with open("gamemessage", "rb") as f:
    data = f.read()
data = bytearray(data)
for i in range(len(data)):
    data[i] ^= 34
data = aes.decrypt(data)
# print(data[data.index(b"MZ"):])

with open("message", "wb") as f1:
    f1.write(data[data.index(b"MZ"):])

from z3 import BitVec, sat, Solver

s = Solver()
x = BitVec("x", 64)
y = BitVec("y", 64)
z = BitVec("z", 64)
KeyStream = [BitVec(f"KeyStream{i}", 64) for i in range(40)]
num = -1
for i in range(120):
    x = (((x >> 29 ^ x >> 28 ^ x >> 25 ^ x >> 23) & 1) | x << 1)
    y = (((y >> 30 ^ y >> 27) & 1) | y << 1)
    z = (((z >> 31 ^ z >> 30 ^ z >> 29 ^ z >> 28 ^ z >> 26 ^ z >> 24) & 1) | z << 1)
    if i % 8 == 0:
        num += 1
    KeyStream[num] = ((KeyStream[num] << 1) | (((z >> 32 & 1 & (x >> 30 & 1)) ^ (((z
                                                                       >> 32 & 1) ^ 1) & (
                                                                             y >> 31 & 1))) & 0xffffffff) & 0xff)
first = [101, 5, 80, 213, 163, 26, 59, 38, 19, 6, 173, 189, 198, 166, 140, 183, 42, 247, 223, 24, 106, 20, 145, 37, 24,
         7, 22, 191, 110, 179, 227, 5, 62, 9, 13, 17, 65, 22, 37, 5]
for i in range(len(first)):
     s.add(first[i] == KeyStream[i])
if s.check() == sat:
     ans = s.model()
     # print(ans)


x = 156324965
y = 868387187
z = 3131229747
array = []
array += [x, y, z]
print(array)
Key = [0] * 12
for i in range(3):
     for j in range(4):
          Key[i*4+j] = (array[i] >> j * 8 & 255)
print(Key)
array5 = [60, 100, 36, 86, 51, 251, 167, 108, 116, 245, 207, 223, 40, 103, 34, 62, 22, 251, 227]
for i in range(len(array5)):
     array5[i] ^= Key[i%12]
print("".join(map(chr, array5)))
