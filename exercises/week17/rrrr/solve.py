cmp = [15, -121, 98, 20, 1, -58, -16, 33, 48, 17, 80, -48, -126, 35, -82, 35, -18, -87, -76, 82, 120, 87, 12, -122, -117]
s = "1A2F943C4D8C5B6EA3C9BCAD7E"
for i in range(len(cmp)):
    cmp[i] &= 0xff
    cmp[i] ^= int(s[i:i+2], 16)
    cmp[i] = (cmp[i] << 6) & 0xff | (cmp[i] >> 2)
print("".join(map(chr, cmp)))
