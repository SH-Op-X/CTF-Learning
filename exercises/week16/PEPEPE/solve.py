s = "This program cannot be run in DOS mode."
c = [0xDE, 0xB6, 0xE4, 0xE9, 0xA9, 0xEA, 0xFF, 0xF9, 0xFD, 0xFF, 0xE9, 0xFB, 0xB3, 0xF0, 0xF2, 0xF8,
0xFA, 0xF5, 0xF2, 0xB0, 0xE8, 0xBB, 0xAD, 0xE8, 0xFC, 0xF4, 0xAD, 0xFF, 0xF4, 0xAD, 0xCC, 0xD9,
0xC0, 0xB3, 0xFE, 0xF9, 0xF0, 0xFF, 0xA8
]
for i in range(len(c)):
    print(chr(0xff-(ord(s[i])^c[i])), end="")

key = b"reverierwilllikeyou!"
with open("file", "rb") as f:
    data = list(f.read())
for i in range(len(data)):
    data[i] ^= key[i%len(key)]
    data[i] = 0xff - data[i]
with open("file.exe", "wb") as f:
    f.write(bytes(data))