s = [0xBC8FF26D43536296, 0x520100780530EE16, 0x4DC0B5EA935F08EC, 0x342B90AFD853F450, 0x8B250EBCAA2C3681, 0x55759F81A2C68AE4]
new_s = []
for v10 in s:
    for i in range(64):
        bit = v10 & 1
        if bit:
            v10 ^= 0xB0004B7679FA26B3
        v10 >>= 1
        if bit:
            v10 |= 0x8000000000000000
    new_s.append(v10)
print("".join([bytes.fromhex(hex(i)[2:]).decode()[::-1] for i in new_s]))