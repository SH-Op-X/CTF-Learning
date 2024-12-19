opcode = [0x00000008, 0x00000001, 0x00000000, 0x00000008, 0x00000003, 0x00000046, 0x0000000E, 0x00000015, 0x0000000A, 0x00000001, 0x00000009, 0x00000002, 0x0000000B, 0x0000000A, 0x00000001, 0x0000000A, 0x00000002, 0x00000009, 0x00000001, 0x00000011, 0x00000001, 0x0000000D, 0x00000001, 0x00000003, 0x0000000F, 0x00000008, 0x00000008, 0x00000001, 0x00000000, 0x00000008, 0x00000003, 0x00000047, 0x0000000E, 0x00000046, 0x0000000A, 0x00000001, 0x0000001A, 0x00000002, 0x00000006, 0x0000001D, 0x00000001, 0x00000004, 0x00000014, 0x00000002, 0x00000001, 0x00000019, 0x00000001, 0x00000002, 0x0000001B, 0x00000001, 0x00000001, 0x0000001D, 0x00000001, 0x0000006E, 0x00000013, 0x00000001, 0x00000063, 0x00000015, 0x00000001, 0x00000074, 0x00000013, 0x00000001, 0x00000066, 0x0000001C, 0x00000002, 0x00000001, 0x00000009, 0x00000001, 0x00000011, 0x00000001, 0x0000000D, 0x00000001, 0x00000003, 0x0000000F, 0x00000022, 0x00000064, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000]
ip = 0
r = [0] * 4
stack = [0] * 5120
while True:
    if opcode[ip] == 8:
        print(f"mov r{opcode[ip + 1] - 1}, {opcode[ip + 2]}")
        r[opcode[ip + 1] - 1] = opcode[ip + 2]
        ip += 3
    elif opcode[ip] == 9:
        print(f"pop r{opcode[ip + 1] - 1}")
        ip += 2
    elif opcode[ip] == 10:
        print(f"push r{opcode[ip + 1] - 1}")
        ip += 2
    elif opcode[ip] == 11:
        print("mov r0, getchar()")
        ip += 1
    elif opcode[ip] == 12:
        print("putchar(r0)")
        ip += 1
    elif opcode[ip] == 13:
        print(f"flag = 224 if r{opcode[ip + 1] - 1} = r{opcode[ip + 2] - 1}")
        print(f"flag = 32 if r{opcode[ip + 1] - 1} > r{opcode[ip + 2] - 1}")
        print(f"flag = 64 if r{opcode[ip + 1] - 1} < r{opcode[ip + 2] - 1}")
        ip += 3
    elif opcode[ip] == 14:
        print(f"jmp {opcode[ip + 1]}")
        ip = opcode[ip + 1]
    elif opcode[ip] == 15:

    elif opcode[ip] == 16:
    elif opcode[ip] == 17:
    elif opcode[ip] == 18:
    elif opcode[ip] == 19:
    elif opcode[ip] == 20:
    elif opcode[ip] == 21:
    elif opcode[ip] == 22:
    elif opcode[ip] == 23:
    elif opcode[ip] == 24:
    elif opcode[ip] == 25:
    elif opcode[ip] == 26:
    elif opcode[ip] == 27:
    elif opcode[ip] == 28:
    elif opcode[ip] == 29:
