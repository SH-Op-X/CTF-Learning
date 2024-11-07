import base64

correct_table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
table = correct_table[10:20][::-1] + correct_table[0:10][::-1] + correct_table[20:]
print(table)
c = 'd2G0ZjLwHjS7DmOzZAY0X2lzX3CoZV9zdNOydO9vZl9yZXZlcnGlfD=='
new_c = []
for i in range(len(c)):
    if c[i] != '=':
        new_c.append(correct_table[table.index(c[i])])
    else:
        new_c.append(c[i])
print(''.join(new_c))
print(base64.b64decode(''.join(new_c)).decode())