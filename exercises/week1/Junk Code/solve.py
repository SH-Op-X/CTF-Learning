s = "NRQ@PC}Vdn4tHV4Yi9cd#\\}jsXz3LMuaaY0}nj]`4a5&WoB4glB7~u"
flag = ""
for i in range(len(s)):
    flag += chr(ord(s[i])^(i%9))
print(flag)