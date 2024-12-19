import hashlib
a = 'deadbeaf'
b = '3&!2309'
c = 4
for i in range(0, 6):
    if i >= 3:
        st = a * (c - i) + b * (c + i)
    else:
        st = a * (c + i) + b * (c - i)
    m = hashlib.md5()
    m.update(st)
    print m.hexdigest()