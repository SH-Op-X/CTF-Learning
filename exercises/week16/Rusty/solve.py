from z3 import *

s = Solver()

cmp = [0x0145, 0x0144, 0x013B, 0x011B, 0x00FB, 0x00FB, 0x0120, 0x013C, 0x0151, 0x0142, 0x0147, 0x013B, 0x0141, 0x012C, 0x0140, 0x0119, 0x0119, 0x0116, 0x0147, 0x015D, 0x0143, 0x0135, 0x0132, 0x0138, 0x0136, 0x0130, 0x013A, 0x014A, 0x0149, 0x0143, 0x0142, 0x013E, 0x0134, 0x00FA, 0x00F2, 0x00D9, 0x00E6, 0x00D2, 0x00D1, 0x00D6, 0x00D7, 0x00D3, 0x00D4, 0x00A9, 0x0089, 0x0063, 0x0063, 0x00BF]
print(len(cmp))
a = [BitVec(f"a{i}", 9) for i in range(50)]
for i in range(48):
    s.add(a[i]+a[i+1]+a[i+2]==cmp[i])
    s.add(a[i]<127)
    s.add(a[i]>32)
s.add(a[49]==ord("}"))
if s.check() == sat:
    ans = s.model()
    for i in a:
        print(chr(ans[i].as_long()), end="")

