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
        i = (i + 1) % 256
        j = (j + S[i]) % 256
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


if __name__ == "__main__":
    key = [0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78]
    text = [0x56, 0x05, 0x03, 0x86, 0x7D, 0xEC, 0xF9, 0xAB, 0x26, 0xAA, 0x2D, 0x10, 0xB1, 0xD9, 0xD5, 0x8D, 0x0F, 0xC6, 0x49, 0xA7, 0xFB, 0x9D, 0xB1, 0xA4, 0x4D, 0x2D, 0x85, 0x2F, 0x9A]
    print(len(text))
    print(RC4(key, text))
    print(RC4(key, text).decode())
