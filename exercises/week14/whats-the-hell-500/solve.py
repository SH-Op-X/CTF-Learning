from z3 import *

s = Solver()
p = [Int(f"p{i}") for i in range(13)]
cmp = [101, 143, 5035, 163, 226, 5814, 205, 173, 9744, 5375, 4670, 205]
s.add(p[0]+p[1]==101)
s.add(p[1]+p[2]==143)
s.add(p[0]*p[2]==5035)
s.add(p[3]+p[5]==163)
s.add(p[3]+p[4]==226)
s.add(p[4]*p[5]==5814)
s.add(p[7]+p[8]==205)
s.add(p[6]+p[8]==173)
s.add(p[6]*p[7]==9744)
s.add(p[9]+p[10]*p[11]==5375)
s.add(p[10]+p[9]*p[11]==4670)
s.add(p[9]+p[10]==205)
s.add(p[12]==ord("w"))
for i in range(13):
    s.add(p[i] < 128)
if s.check() == sat:
    ans = s.model()
    for i in p:
        print(chr(ans[i].as_long()), end="")