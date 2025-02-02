# from pwn import *
#
# # 定义可打印的 ASCII 字符范围
# PRINTABLE_RANGE = range(0x20, 0x7F)  # 从空格 (0x20) 到 ~ (0x7E)
#
# def test_segFix():
#     # 记录导致崩溃的字符
#     crash_chars = []
#
#     for char_code in PRINTABLE_RANGE:
#         char = chr(char_code)  # 将 ASCII 码转换为字符
#         print(f"Testing character: {char} (ASCII: {char_code})")
#
#         # 启动目标程序
#         p = process('./segFix')
#
#         # 等待程序输出 "Provide input:"
#         p.recvuntil(b"Provide input:\n")
#
#         # 发送当前字符并回车
#         p.sendline(char.encode())
#
#         # 尝试接收程序的输出
#         try:
#             output = p.recv(timeout=1)  # 设置超时时间为1秒
#             print(f"Program output: {output.decode().strip()}")
#         except EOFError:
#             # 如果程序崩溃，记录导致崩溃的字符
#             print("Program crashed with segmentation fault.")
#             crash_chars.append(char)
#         except Exception as e:
#             # 处理其他异常
#             print(f"An error occurred: {e}")
#         finally:
#             # 关闭进程
#             p.close()
#
#     # 输出测试结果
#     if crash_chars:
#         print("\nCharacters that caused a crash:")
#         for char in crash_chars:
#             print(f"  - {char} (ASCII: {ord(char)})")
#     else:
#         print("\nNo characters caused a crash.")
#
# if __name__ == "__main__":
#     test_segFix()


s = b"EQVxw6jaWd:oekw>~vMp$qsH)jE}isc"
for i in range(len(s)):
    print(chr(s[i]^i), end="")