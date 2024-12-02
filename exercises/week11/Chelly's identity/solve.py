from gmpy2 import is_prime

prime_list = []
for i in range(128):
    if is_prime(i):
        prime_list.append(i)
print(prime_list)
cmp = [438, 1176, 1089, 377, 377, 1600, 924, 377, 1610, 924, 637, 639, 376, 566, 836, 830]
flag = ""
xor_list = []
for i in range(32, 128):
    sum = 0
    for j in prime_list:
        if j < i:
            sum += j
    xor_list.append(sum^i)
flag = ""
for i in range(len(cmp)):
    flag += chr(xor_list.index(cmp[i])+32)
print(flag)