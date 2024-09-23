def KSA(key):
    """ Key-Scheduling Algorithm (KSA) 密钥调度算法"""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def PRGA(S):
    """ Pseudo-Random Generation Algorithm (PRGA) 伪随机数生成算法"""
    i, j = 0, 0
    while True:
        i = (i + 3) % 256
        j = (j + S[i] + 1) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        yield K


def RC4(key, text):
    """ RC4 encryption/decryption """
    S = KSA(key)
    keystream = PRGA(S)
    res = []
    for char in text:
        res.append(char ^ next(keystream))
    return bytes(res)


out = [0x0000004D, 0xFFFFFFE6, 0x00000049, 0xFFFFFF95, 0x00000003, 0x0000002D, 0x0000002B, 0xFFFFFFBA, 0xFFFFFFEA, 0x0000006D, 0xFFFFFFFF, 0x00000059, 0x00000070, 0x00000000, 0x0000001B, 0xFFFFFFA9, 0x0000002C, 0xFFFFFFB0, 0x00000032, 0xFFFFFF98, 0x0000006F, 0xFFFFFF8C, 0x00000056, 0xFFFFFFA2, 0x0000004C, 0x00000079, 0x0000007F]
out = [i&0xff for i in out]
for i in range(len(out)-1, -1, -1):
    out[i] = out[i]^out[(i+1)%len(out)]
key = b'Hello_Ctfers!!!\x00'
print(RC4(key, out))