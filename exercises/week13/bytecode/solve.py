cmp = [25, 108, 108, 176, 18, 108, 110, 177, 64, 29, 134, 29, 187, 103, 32, 139, 144, 179, 134, 177, 32, 24, 144, 25, 111, 14, 111, 14]
print(len(cmp))
for j in range(len(cmp)):
    for i in range(32, 127):
        if i * 39 % 196 == cmp[j]:
            print(chr(i), end="")
            break