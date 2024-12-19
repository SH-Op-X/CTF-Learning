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
    for i in range(len(text)):
        res.append(text[i] ^ next(keystream) ^ 39)
    return bytes(res)


if __name__ == "__main__":
    key = b"2021quickjs_happygame"
    text = [150, 224, 244, 68, 61, 125, 8, 239, 203, 254, 241, 113, 213, 176, 64, 106, 103, 166, 185, 159, 158, 172, 9, 213, 239, 12, 100, 185, 90, 174, 107, 131, 223, 122, 229, 157]
    print(len(text))
    print(RC4(key, text).decode())
