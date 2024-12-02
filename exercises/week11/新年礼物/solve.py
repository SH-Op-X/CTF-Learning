from hashlib import sha256
hash_value = sha256(b"NSSCTF2024").hexdigest()[:8]
hash_value = [int(i, 16) for i in hash_value]
enc = [129,75,102,116,123,118,103,127,122,126,105,114,103,105,126,105,122,122,97,76,103,110,103,122,118,124,114,111,109,112,115,109,118,112,100,111,98,103,125,141,115,32,121,112,102,122,123,118,101,126,107,119,119,143,111,100,126,107,122,118,123,118,107,114,102,102,126,127,118,121,135]
num = 0
key = hash_value[-1]
flag = "NSSCTF"
for i in range(len(enc)):
    flag += chr(((enc[i] ^ hash_value[(num + 1) % 7]) - hash_value[num % 7])&0xff)
    num += key
print(flag)
