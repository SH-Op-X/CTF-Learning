# 读取文件并提取每列的数据
class CODE:
    def __init__(self, index, dis):
        self.index = index
        self.dis = dis
def extract_columns_from_file(file_path):
    # 打开文件并读取所有行
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    codes = []
    # 处理每一行，提取每一列的数据
    for i in range(12, len(lines)):
        line = lines[i]
        # 去除行首尾的空白符，并按'|'分割
        parts = line.strip().split('\t')
        # 确保行包含至少7个部分，防止异常
        if len(parts) >= 4:
            dis = parts[2].strip()
            if "Debug event" in dis:
                continue
            if "jmp     cs:" in dis:
                continue
            code = CODE(i, dis)
            codes.append(code)
            # 返回每列的数据作为结果
    return codes

file_path = 'trace.txt'
codes = extract_columns_from_file(file_path)

final_codes = []
for i in range(len(codes) - 1):
    insert1 = 0
    insert2 = 0
    code = codes[i]
    if codes[i - 1].dis == "popfq" and codes[i + 1].dis == "push    rbx":
        insert1 = 1
    if codes[i - 1].dis == "retn" and codes[i + 1].dis == "push    rbx":
        insert2 = 1
    if insert1 == 1 or insert2 == 1:
        final_codes.append(code)
for i in range(len(final_codes)):
    code = final_codes[i]
    print(f"{code.dis}")