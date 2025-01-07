import struct


# 宏定义：循环左移（左移操作后，右边溢出的部分重新回到左边）
def ROTL(a, b):
    return ((a << b) & 0xFFFFFFFF) | (a >> (32 - b))


# 宏定义：Chacha20的四分之一轮（Quarter Round）操作
def QR(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = ROTL(d, 16)
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = ROTL(b, 12)
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = ROTL(d, 8)
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = ROTL(b, 7)
    return a, b, c, d


# ChaCha20加密算法中的块函数
def chacha20_block(output, input_state):
    x = list(input_state)

    # 进行20轮加密操作，每轮执行四分之一轮操作
    for _ in range(10):
        # 奇数轮
        x[0], x[4], x[8], x[12] = QR(x[0], x[4], x[8], x[12])
        x[1], x[5], x[9], x[13] = QR(x[1], x[5], x[9], x[13])
        x[2], x[6], x[10], x[14] = QR(x[2], x[6], x[10], x[14])
        x[3], x[7], x[11], x[15] = QR(x[3], x[7], x[11], x[15])

        # 偶数轮
        x[0], x[5], x[10], x[15] = QR(x[0], x[5], x[10], x[15])
        x[1], x[6], x[11], x[12] = QR(x[1], x[6], x[11], x[12])
        x[2], x[7], x[8], x[13] = QR(x[2], x[7], x[8], x[13])
        x[3], x[4], x[9], x[14] = QR(x[3], x[4], x[9], x[14])

    # 将加密结果与原始输入状态相加，输出最终结果
    for i in range(16):
        output[i] = (x[i] + input_state[i]) & 0xFFFFFFFF


# ChaCha20加密函数
def chacha20_encrypt(out, in_data, in_len, key, nonce, counter):
    state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,  # 固定常量（ASCII编码：expand 32-byte k）
        key[0], key[1], key[2], key[3],  # 256位密钥（8个32位字）
        key[4], key[5], key[6], key[7],
        counter, nonce[0], nonce[1], nonce[2]  # 计数器和nonce
    ]

    block = [0] * 16  # 存储每次生成的64字节的加密块
    while in_len > 0:
        # 生成一个加密块
        chacha20_block(block, state)
        state[12] = (state[12] + 1) & 0xFFFFFFFF  # 每次加密后递增计数器

        block_size = min(in_len, 64)  # 计算当前块的大小
        for i in range(block_size):
            out[i] = in_data[i] ^ (block[i // 4] >> (8 * (i % 4)) & 0xFF)  # 将输入数据与加密块异或得到密文

        # 更新剩余输入数据的长度和指针
        in_len -= block_size
        in_data = in_data[block_size:]
        out = out[block_size:]


# 主函数
def main():
    # 示例：初始化密钥、nonce、明文等
    key = [0x57, 0xEE, 0x23, 0x50, 0x80, 0xA2, 0x05, 0x6A, 0x05, 0x40, 0x12, 0x73, 0xEC, 0xEB, 0xCF, 0x12,
           0xC4, 0x18, 0xD9, 0x9E, 0xD2, 0xC3, 0x60, 0xF0, 0x72, 0x5B, 0x17, 0xDB, 0x36, 0x30, 0x61, 0x45]  # 32字节的密钥
    nonce = [0xE6, 0x37, 0x13, 0x8A, 0xBD, 0x83, 0x3D, 0x14, 0x95, 0xA9, 0x9B, 0x90]  # 12字节的nonce
    key = [struct.unpack("<I", bytes(key[i:i+4]))[0] for i in range(0, len(key), 4)]
    nonce = [struct.unpack("<I", bytes(nonce[i:i+4]))[0] for i in range(0, len(nonce), 4)]
    plaintext = b"Hello, this is a test for the ChaCha20 encryption algorithm."  # 明文
    ciphertext = [0x5E, 0xC0, 0x7C, 0x75, 0x73, 0x4B, 0xCE, 0x23, 0xA4, 0xBB, 0x89, 0xAC, 0xF3, 0x01, 0x8F, 0x70,
                  0xC8, 0x7F, 0x31, 0x83, 0x41, 0x5B, 0xD4, 0x62, 0xA6, 0xA7, 0x27, 0xDC, 0x9D, 0xFC, 0x50, 0x4B,
                  0x06, 0x98, 0x2F, 0x6B, 0x38, 0x17, 0x51, 0x38, 0x2F, 0xEF]  # 密文

    # 对密文进行预处理
    for i in range(42):
        ciphertext[i] = (ciphertext[i] - i) & 0xFF

    # 执行解密操作（加密是对称的，解密过程与加密相同）
    decrypted = bytearray(len(ciphertext))
    chacha20_encrypt(decrypted, ciphertext, len(ciphertext), key, nonce, 0x9E3779B9)

    # 解密后的数据应当与原始明文相同
    print(decrypted.decode('utf-8'))


if __name__ == "__main__":
    main()