# Source Generated with Decompyle++
# File: pyc.pyc (Python 3.10)

import hashlib
s = input()
if len(s) != 72:
    print('wrong')
a1 = set()
a2 = set()
a3 = set()
a4 = [
    0x9E3779B9,
    0x9E3779B9]
for d in '012345678':
    a3.add(s.count(d))     # 所有都出现且出现次数相同才能保证a3长度为1，或者都不出现
for i in range(0, len(s), 9):
    for l in range(0, 15, 2):
        a2.add(sum([s[i + j] for j in [int(c) for c in str(a4[1] ^ 0xE4172600000000 ^ 0xCD70877A)[l:l + 3])[l:l + 3]]]))
#         a2.add(sum((lambda .0: for j in .0:
# int(s[i + j:i + j + 1]))((lambda .0: [ int(v) for v in .0 ])(str(a4[1] ^ 0xE4172600000000 ^ 0xCD70877A)[l:l + 3]))))
    if int(s[i:i + 9]) >= a4[0]:    # 每次都不满足，即每9位数都在变小，且不相等
        pass
    else:
        a4[0] = int(s[i:i + 9])
        a1.add(s[i:i + 9])
    if len(a1) == 8 and len(a2) == 1 and len(a3) == 1 and s.count('9') == 0:    # 不出现9
        print(f'''flag{{{hashlib.md5(s.encode('ascii')).hexdigest()}}}''')
        return None
    None(print)
    return None
