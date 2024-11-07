with open("key") as f1:
    key = f1.read().splitlines()[:-1]
with open("encrypted.qr") as f2:
    c = f2.read().splitlines()
print(key)
c = [list(map(int, i)) for i in c]
print(c)
for k in key:
    v = int(k[0])
    id1 = int(k.split(",")[0].split("(")[-1])
    id2 = int(k.split(",")[1][:-1])
    if v == 0:
        c[id2][id1] += c[id2][id1-1]
        c[id2][id1-1] = c[id2][id1] - c[id2][id1-1]
        c[id2][id1] -= c[id2][id1-1]
    elif v == 1:
        c[id2][id1] += c[id2][id1+1]
        c[id2][id1+1] = c[id2][id1] - c[id2][id1+1]
        c[id2][id1] -= c[id2][id1+1]
    elif v == 2:
        c[id2][id1] += c[id2-1][id1]
        c[id2-1][id1] = c[id2][id1] - c[id2-1][id1]
        c[id2][id1] -= c[id2-1][id1]
    elif v == 3:
        c[id2][id1] += c[id2+1][id1]
        c[id2+1][id1] = c[id2][id1] - c[id2+1][id1]
        c[id2][id1] -= c[id2+1][id1]
c = "".join(["".join(map(str, i)) for i in c])
print(c)

from PIL import Image
MAX = 25
pic = Image.new("RGB", (MAX, MAX))
i = 0
for y in range(0, MAX):
    for x in range(0, MAX):
        if c[i] == '1':
            pic.putpixel((x, y), (0, 0, 0))
        else:
            pic.putpixel((x, y), (255, 255, 255))
        i += 1
pic.show()
pic.save("flag.png")

