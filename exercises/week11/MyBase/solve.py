import base64
tables = ["+86420ywusqomkigecaYWUSQOMKIGECABDFHJLNPRTVXZbdfhjlnprtvxz13579/",
"YsVO0tvT2o4puZ38j1dwf7MArGPNeQLDRHUK+SChbFanmklWEcgixXJIq6y5B/9z=",
"xDfpNE4LYH5Tk+MRtrlv1oFbQm0gP37eqIajh2syUnZcSV8iBK6O/XWuzdCwA9GJ=",
"YvHeOZECmTyg0Mw2i7PIGKblsfF59rzUk6p3hVdW1qaQ+xRANnXLj48BcJDotS/u=",
"xDfpNE4LYH5Tk+MRtrlv1oFbQm0gP37eqIajh2syUnZcSV8iBK6O/XWuzdCwA9GJ=",
"YvHeOZECmTyg0Mw2i7PIGKblsfF59rzUk6p3hVdW1qaQ+xRANnXLj48BcJDotS/u=",
"xDfpNE4LYH5Tk+MRtrlv1oFbQm0gP37eqIajh2syUnZcSV8iBK6O/XWuzdCwA9GJ=",
"YvHeOZECmTyg0Mw2i7PIGKblsfF59rzUk6p3hVdW1qaQ+xRANnXLj48BcJDotS/u=",
"xDfpNE4LYH5Tk+MRtrlv1oFbQm0gP37eqIajh2syUnZcSV8iBK6O/XWuzdCwA9GJ="]
cmp = "YkLYv1Xj23X7N0E5eoFgUveKeos1XS8K9r4g"
for i in range(9):
    correct_table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    table = tables[i]
    c = cmp[i*4:i*4+4][::-1]
    new_c = []
    for i in range(len(c)):
        if c[i] != '=':
            new_c.append(correct_table[table.index(c[i])])
        else:
            new_c.append(c[i])
    print(base64.b64decode(''.join(new_c)).decode(), end="")