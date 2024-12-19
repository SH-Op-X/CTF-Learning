from hashlib import md5
c = [723048561,705246381,561048723,507642183,381246705,327840165,183642507,165840327]
s = "".join(map(str, c))
print(f"flag{{{md5(s.encode()).hexdigest()}}}")