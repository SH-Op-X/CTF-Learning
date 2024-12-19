with open("hash.pyc", "rb") as f:
    data = f.read()
with open("Jhash.pyc", "rb") as f1:
    data1 = f1.read()
change_dict = {}
for i in range(len(data)):
    if data1[i] != data[i]:
        change_dict[data1[i]] = data[i]
print(change_dict)
# with open("Jflag.pyc", "rb") as f2:
#     data2 = f2.read()
# new_data = []
# for i in range(len(data2)):
#     if data2[i] in change_dict.keys():
#         new_data.append(change_dict[data2[i]])
#     else:
#         new_data.append(data2[i])
# with open("new-Jflag.pyc", "wb") as f3:
#     f3.write(bytes(new_data))
from base64 import b64decode
s = b'^P]mc@]0emZ7VOZ2_}A}VBwpbQ?5e5>lN4UwSSM>L}A}'
print(len(s))
flag = ""
for i in range(len(s)):
    if s[i] == 90:
        flag += chr(69^7)
    else:
        flag += chr(s[i]^7)
print(flag)
print(b64decode(flag.encode()).decode())