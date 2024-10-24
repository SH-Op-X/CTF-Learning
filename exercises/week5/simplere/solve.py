s = "*A**********.***.....**.....***.*********..*********B**"
print(len(s))
for i in range(1, len(s)-1):
    print(s[i-1], end="")
    if i % 11 == 0:
        print()
print()

print(len("ssddddwddddssas"))

import base64
correct_table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
table = 'sZGad02wvbf3mtxEq8rDhYK47LueClz1Jig6ypHM+o/W5QjNPFRckUInOTXVAS9B'
c = 'r60ihyZ/m4lseHt+m4t+mIkc'
new_c = []
for i in range(len(c)):
    if c[i] != '=':
        new_c.append(correct_table[table.index(c[i])])
    else:
        new_c.append(c[i])
print(base64.b64decode(''.join(new_c)).decode())