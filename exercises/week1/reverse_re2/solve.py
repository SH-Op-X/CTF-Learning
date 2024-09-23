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
    key = b"12345678"
    text = [0xDD, 0x9F, 0x58, 0xB3, 0x72, 0xC8, 0xB1, 0xD2, 0x91, 0x41, 0x6F, 0xBB, 0xC9, 0x5C, 0x7B, 0xC1, 0x13, 0xED, 0xFB, 0x28, 0xB3, 0x10, 0xB, 0xCF, 0x21, 0x68, 0xA2, 0x86, 0x6B, 0x9E, 0x90, 0x1D, 0xCA, 0xF4, 9, 0x1E, 0xE8, ord("y"), ord("j")]
    print(RC4(key, text))
    print(RC4(key, text).decode())
