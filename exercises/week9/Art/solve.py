import hashlib


target_hash = "40F53FF2B934DA894ED3FF1F6E76C68A30ED92BCF764E839D5B31196D0899287"  # 目标MD5值
# Str2的字节数组
Str2 = [0x02, 0x18, 0x0F, 0xF8, 0x19, 0x04, 0x27, 0xD8, 0xEB, 0x00,
        0x35, 0x48, 0x4D, 0x2A, 0x45, 0x6B, 0x59, 0x2E, 0x43, 0x01,
        0x18, 0x5C, 0x09, 0x09, 0x09, 0x09, 0xB5, 0x7D]
# 计算MD5哈希
def md5_check(data):
    if hashlib.sha256("".join(map(chr, data[::-1])).encode('utf-8')).hexdigest().upper() == target_hash:
        print("".join(map(chr, data[::-1])))
        exit(0)


# 从最后一个字符往前推导
def dfs(current_str):
    if len(current_str) == 28:
        md5_check(current_str)
        return
    for i in range(32, 128):
        if i ^ (i % 17 + current_str[-1]) ^ 0x19 == Str2[-len(current_str)-1]:
            dfs(current_str+[i])
    return


# 求解函数
def solve(Str2):
    # 从最后一个字符开始调用DFS
    initial_str = [0x7d]  # 最后一个字符是0x70
    dfs(initial_str)



# 开始求解
solve(Str2)
