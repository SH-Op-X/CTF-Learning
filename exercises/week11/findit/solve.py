import copy

cmp = [29, 70, 92, 84, 87, 19, 61, 43, 62, 60, 29, 9, 18, 63, 6, 6, 42, 14, 124, 110, 109, 60, 105, 160, 184, 135, 62, 128, 92, 61, 220, 176]
def dfs(cmp, index):
    if index == -1:
        key = b"HN_CTF"
        for i in range(len(cmp)):
            cmp[i] ^= key[i//4%6]
        for i in range(0, len(cmp), 4):
            cmp[i], cmp[i+1], cmp[i+2], cmp[i+3] = cmp[i+3], cmp[i], cmp[i+2], cmp[i+1]
        print("".join(map(chr, cmp)))
    for i in range(256):
        if cmp[index+1] ^ i ^ ((i + 12) % 24) ^ (index+18) == cmp[index]:
            tmp = copy.deepcopy(cmp)
            tmp[index] = i
            dfs(tmp, index-1)

dfs(cmp, 30)
