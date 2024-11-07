# from base64 import b64decode
#
# base64_c = "VUiD7FBIjWwkIEiJTUBIi0VAiwCJRQC4BAAAAEgDRUCLAIlFBMdFCAAAAADHRQwj782rx0UQFgAAAMdFFCEAAADHRRgsAAAAx0UcNwAAAMdFIAAAAACLRSCD+CBzWotFDANFCIlFCItFBMHgBANFEItVCANVBDPCi1UEweoFA1UUM8IDRQCJRQCLRQDB4AQDRRiLVQgDVQAzwotVAMHqBQNVHDPCA0UEiUUEuAEAAAADRSCJRSDrnkiLRUCLVQCJELgEAAAASANFQItVBIkQSI1lMF3D"
# content = b64decode(base64_c.encode())
# print(content)
# with open("shellcode", "wb") as f:
#     f.write(content)
import struct
from ctypes import c_uint32
from Crypto.Util.number import bytes_to_long

def tea_decrypt(r, v, key, delta):
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    total = c_uint32(-delta * r)
    for i in range(r):
        v1.value -= ((v0.value << 4) + key[2]) ^ (v0.value + total.value) ^ ((v0.value >> 5) + key[3])
        v0.value -= ((v1.value << 4) + key[0]) ^ (v1.value + total.value) ^ ((v1.value >> 5) + key[1])
        total.value += delta
    return v0.value, v1.value

k = [22, 33, 44, 55]
with open("outputdir/flag.enc", "rb") as f:
    content = f.read()
v = []
for i in range(0, len(content), 4):
    v.append(bytes_to_long(content[i:i+4][::-1]))
delta = 0x543210DD
for i in range(0, len(v), 2):
    v[i:i+2] = tea_decrypt(32, v[i:i+2], k, delta)
str_list = []
for i in range(len(v)):
    str_list.append(struct.pack('<I', v[i]).decode())
print('decrypted: %s' % ''.join(str_list))