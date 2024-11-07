from hashlib import md5, sha256, sha512
from itertools import product
from string import ascii_lowercase, digits

char_list = list(ascii_lowercase + digits + "-")
print(char_list)
flag = "87f645e9-b628-412f-9d7a-"
for i in product(char_list, repeat=4):
    word = "".join(i)
    if sha256(word.encode()).hexdigest() == "6e2b55c78937d63490b4b26ab3ac3cb54df4c5ca7d60012c13d2d1234a732b74":
        flag += word
for i in product(char_list, repeat=4):
    word = "".join(i)
    if sha512(word.encode()).hexdigest() == "6500fe72abcab63d87f213d2218b0ee086a1828188439ca485a1a40968fd272865d5ca4d5ef5a651270a52ff952d955c9b757caae1ecce804582ae78f87fa3c9":
        flag += word
for i in product(char_list, repeat=4):
    word = "".join(i)
    if md5(word.encode()).hexdigest() == "ff6e2fd78aca4736037258f0ede4ecf0":
        flag += word
print(flag)