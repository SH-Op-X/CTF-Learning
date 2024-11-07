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
        char = text[i]
        res.append(char ^ next(keystream) ^ i)
    return bytes(res)


if __name__ == "__main__":
    key = b"G0@K3yn3SC1f"
    data = [0xAE4B31801A7119AE, 0xD755266F17FE6B60, 0x4A525D977BABB405, 0x53B3C2A02AD7E331, 0x1F074D2BAE2BAB1C, 0xF6ADCEBAF6E436E9]
    text = []
    for i in range(len(data)):
        while data[i]:
            text.append(data[i] & 0xff)
            data[i] >>= 8
    print(list(map(hex, text)))
    print(RC4(key, text))
    print(RC4(key, text).decode())
