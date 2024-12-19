import base64

correct_table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
table = 'YRiAOe4PlGvxaCoNj2ZgX+q8t/5Em6IUpM9FrVb7BKwsT1n3fSydhDWuQHJ0ckzL'
c = 'mWGFL24R/RSZY3pzK9H4FOmFOnXJKyCjXWbZ7Ijy11GbCBukDrjsiPPFiYB='
new_c = []
for i in range(len(c)):
    if c[i] != '=':
        new_c.append(correct_table[table.index(c[i])])
    else:
        new_c.append(c[i])
text = base64.b64decode(''.join(new_c))

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
        yield K, i


def RC4(key, text):
    """ RC4 encryption/decryption """
    S = KSA(key)
    keystream = PRGA(S)
    res = []
    for char in text:
        t, i = next(keystream)
        res.append(char ^ t ^ i)
    return bytes(res)


s = [78, 82, 81, 64, 80, 67, 125, 83, 96, 56, 121, 84, 61, 126, 81, 79, 79, 119, 38, 120, 39, 74, 112, 38, 44, 126, 103]
key = [s[i]^i for i in range(len(s))]
print(bytes(key))
print(RC4(key, text))
print(RC4(key, text).decode())
