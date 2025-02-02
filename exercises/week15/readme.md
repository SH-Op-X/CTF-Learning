# Week 15（2024.12.23-2024.12.29）

## cello-rule

字符串里可以看到很多信息，可以确定是[Cello](https://github.com/orangeduck/Cello-Website/tree/master/static)，由于给的可执行文件符号表缺失（可以看出来很多函数是库函数），因此去编译最新版的代码得到so文件

bindiff处理下可以还原大部分，剩下的结合字符串基本完全还原

~~~c
__int64 __fastcall sub_403079(int a1, __int64 a2)
{//...
  v52[5] = __readfsqword(0x28u);
  if ( a1 <= 1 )
  {
    printf("usage: %s file\n", *a2);
    exit(1);
  }
  v17 = Terminal;
  v18 = &v17;
  memset(v41, 0, sizeof(v41));
  v2 = header_init(v41, Tuple, 2LL);
  *v2 = v18;
  memset(v40, 0, sizeof(v40));
  v3 = header_init(v40, off_636460, 2LL);
  *v3 = rand_what;
  v29 = call_with(v3, v2);
  v33 = *v29;
  v34 = 30LL;
  memset(v52, 0, 40);
  v4 = header_init(v52, off_6332D0, 2LL);
  v5 = v34;
  *v4 = v33;
  v4[1] = v5;
  v35[0] = v4;
  v35[1] = Terminal;
  v19 = v35;
  memset(v42, 0, sizeof(v42));
  v6 = header_init(v42, Tuple, 2LL);
  *v6 = v19;
  v30 = new_with(off_6332D0, v6);
  v20 = *(a2 + 8);
  memset(v44, 0, sizeof(v44));
  v7 = header_init(v44, off_639A70, 2LL);
  *v7 = v20;
  v36[0] = v7;
  v36[1] = Terminal;
  v21 = v36;
  memset(v43, 0, sizeof(v43));
  v8 = header_init(v43, Tuple, 2LL);
  *v8 = v21;
  v31 = new_with(off_639A70, v8);
  v37[0] = v31;
  v37[1] = Terminal;
  v23 = v37;
  memset(v46, 0, sizeof(v46));
  v9 = header_init(v46, Tuple, 2LL);
  *v9 = v23;
  v22 = read_flag_file;
  memset(v45, 0, sizeof(v45));
  v10 = header_init(v45, off_636460, 2LL);
  *v10 = v22;
  v32 = call_with(v10, v9);
  v38[0] = v32;
  v38[1] = v30;
  v38[2] = Terminal;
  v25 = v38;
  memset(v48, 0, sizeof(v48));
  v11 = header_init(v48, Tuple, 2LL);
  *v11 = v25;
  v24 = encode;
  memset(v47, 0, sizeof(v47));
  v12 = header_init(v47, off_636460, 2LL);
  *v12 = v24;
  call_with(v12, v11);
  v26 = ".enc";
  memset(v49, 0, sizeof(v49));
  v13 = header_init(v49, off_639A70, 2LL);
  *v13 = v26;
  append(v31, v13);
  v39[0] = v32;
  v39[1] = v31;
  v39[2] = Terminal;
  v28 = v39;
  memset(v51, 0, sizeof(v51));
  v14 = header_init(v51, Tuple, 2LL);
  *v14 = v28;
  v27 = write_enc_file;
  memset(v50, 0, sizeof(v50));
  v15 = header_init(v50, off_636460, 2LL);
  *v15 = v27;
  call_with(v15, v14);
  return 0LL;
}
~~~

可以发现5个自定义函数

1. rand_what：猜测是生成随机数，核心处理是这句话`v7 |= ~v7 << 32;`，应该是读取了4字节随机数

   ~~~c
   __int64 sub_401AFA()
   {//...
     v15[5] = __readfsqword(0x28u);
     memset(v12, 0, sizeof(v12));
     v0 = header_init(v12, off_639A70, 2);
     *v0 = "/dev/urandom";
     v10[0] = v0;
     memset(v13, 0, sizeof(v13));
     v1 = header_init(v13, off_639A70, 2);
     *v1 = &rb;
     v10[1] = v1;
     v10[2] = Terminal;
     memset(v11, 0, sizeof(v11));
     v2 = header_init(v11, Tuple, 2);
     *v2 = v10;
     v8 = new_with(off_635DE8, v2);
     sread(v8, &v7, 4LL);
     v7 |= ~v7 << 32;
     sclose(v8);
     v6 = v7;
     memset(v15, 0, 32);
     v3 = header_init(v15, off_6333D0, 2);
     *v3 = v6;
     v9[0] = v3;
     v9[1] = Terminal;
     memset(v14, 0, sizeof(v14));
     v4 = header_init(v14, Tuple, 2);
     *v4 = v9;
     return new_with(off_6333D0, v4);
   }
   ~~~

2. read_flag_file：很明显读取文件

   ~~~c
   __int64 __fastcall sub_40158D(__int64 a1)
   {//...
     v34[7] = __readfsqword(0x28u);
     v19[0] = off_6333D0;
     v19[1] = Terminal;
     memset(v26, 0, sizeof(v26));
     v1 = header_init(v26, Tuple, 2);
     *v1 = v19;
     v14 = new_with(off_633D20, v1);
     memset(v28, 0, sizeof(v28));
     v2 = header_init(v28, Int, 2);
     *v2 = 0LL;
     v21[0] = get(a1, v2);
     memset(v29, 0, sizeof(v29));
     v3 = header_init(v29, off_639A70, 2);
     *v3 = &rb;
     v21[1] = v3;
     v21[2] = Terminal;
     memset(v27, 0, sizeof(v27));
     v4 = header_init(v27, Tuple, 2);
     *v4 = v21;
     v15 = new_with(off_635DE8, v4);
     sseek(v15, 0LL, 2LL);
     v16 = stell(v15);
     sseek(v15, 0LL, 0LL);
     memset(v32, 0, sizeof(v32));
     v5 = header_init(v32, Int, 2);
     *v5 = v16 >> 3;
     v20[0] = v5;
     v20[1] = Terminal;
     memset(v31, 0, sizeof(v31));
     v6 = header_init(v31, Tuple, 2);
     *v6 = v20;
     memset(v30, 0, sizeof(v30));
     v7 = header_init(v30, Int, 2);
     *v7 = 0LL;
     v22 = v7;
     v23 = 0LL;
     v24 = 0LL;
     v25 = 0LL;
     memset(v34, 0, 0x38uLL);
     v8 = header_init(v34, Range, 2);
     *v8 = v22;
     v8[1] = v23;
     v8[2] = v24;
     v8[3] = v25;
     v17 = range_stack(v8, v6);
     v18 = instance(v17, off_6370C8);
     for ( i = (*v18)(v17); i != Terminal; i = (*(v18 + 8))(v17, i) )
     {
       sread(v15, &v12, 8LL);
       v11 = v12;
       memset(v33, 0, sizeof(v33));
       v9 = header_init(v33, off_6333D0, 2);
       *v9 = v11;
       push(v14, v9);
     }
     sclose(v15);
     return v14;
   }
   ~~~

3. encode：非常明显了，里面有range来遍历，同时下面的call_with传入了之前读取的数据和随机数

   ~~~c
   __int64 __fastcall sub_4025A2(__int64 a1)
   {// ...
     v33[7] = __readfsqword(0x28u);
     memset(v25, 0, sizeof(v25));
     v1 = header_init(v25, Int, 2);
     *v1 = 0LL;
     v15 = get(a1, v1);	// 类似元组取下标，取出读取文件数据
     memset(v26, 0, sizeof(v26));
     v2 = header_init(v26, Int, 2);
     *v2 = 1LL;
     v16 = get(a1, v2);	// 取出随机数
     v12 = len(v15);
     memset(v29, 0, sizeof(v29));
     v3 = header_init(v29, Int, 2);
     *v3 = v12;
     v19[0] = v3;
     v19[1] = Terminal;
     memset(v28, 0, sizeof(v28));
     v4 = header_init(v28, Tuple, 2);
     *v4 = v19;
     memset(v27, 0, sizeof(v27));
     v5 = header_init(v27, Int, 2);
     *v5 = 0LL;
     v21 = v5;
     v22 = 0LL;
     v23 = 0LL;
     v24 = 0LL;
     memset(v33, 0, 0x38uLL);
     v6 = header_init(v33, Range, 2);
     *v6 = v21;
     v6[1] = v22;
     v6[2] = v23;
     v6[3] = v24;
     v17 = range_stack(v6, v4);	// range(len(read_data))
     v18 = instance(v17, off_6370C8);
     for ( i = (*v18)(v17); i != Terminal; i = (*(v18 + 8))(v17, i) )
     {
       v7 = *get(v15, i);	// 下标取数字，每次取8字节
       v20[0] = v16;
       v20[1] = Terminal;
       memset(v32, 0, sizeof(v32));
       v8 = header_init(v32, Tuple, 2);
       *v8 = v20;
       memset(v31, 0, sizeof(v31));
       v9 = header_init(v31, off_636460, 2);
       *v9 = deal_rand;
       v13 = v7 ^ *call_with(v9, v8);	// 异或了deal_rand(随机数)返回的结果
       memset(v30, 0, sizeof(v30));
       v10 = header_init(v30, off_6333D0, 2);
       *v10 = v13;
       set(v15, i, v10);
     }
     return 0LL;
   }
   ~~~

4. deal_rand：发现是一个自定义的随机数生成

   ~~~c
   __int64 __fastcall deal_rand(__int64 a1)
   {//...
     v51[7] = __readfsqword(0x28u);
     memset(v39, 0, sizeof(v39));
     v1 = header_init(v39, Int, 2);
     *v1 = 0LL;
     v22 = get(a1, v1);
     v19 = 0LL;
     memset(v42, 0, sizeof(v42));
     v2 = header_init(v42, Int, 2);
     *v2 = 0LL;
     v34[0] = v2;
     memset(v43, 0, sizeof(v43));
     v3 = header_init(v43, Int, 2);
     *v3 = 64LL;
     v34[1] = v3;
     memset(v44, 0, sizeof(v44));
     v4 = header_init(v44, Int, 2);
     *v4 = -1LL;
     v34[2] = v4;
     v34[3] = Terminal;
     memset(v41, 0, sizeof(v41));
     v5 = header_init(v41, Tuple, 2);
     *v5 = v34;
     memset(v40, 0, sizeof(v40));
     v6 = header_init(v40, Int, 2);
     *v6 = 0LL;
     v30 = v6;
     v31 = 0LL;
     v32 = 0LL;
     v33 = 0LL;
     memset(v50, 0, 56uLL);
     v7 = header_init(v50, Range, 2);
     *v7 = v30;
     v7[1] = v31;
     v7[2] = v32;
     v7[3] = v33;
     v23 = range_stack(v7, v5);
     v24 = instance(v23, off_6370C8);
     for ( i = (*v24)(v23); i != Terminal; i = (*(v24 + 8))(v23, i) )
     {
       v25 = *v22;
       v8 = *v22 & 1;
       v19 |= v8 << c_int(i);
       *v22 = 0LL;
       memset(v47, 0, sizeof(v47));
       v9 = header_init(v47, Int, 2);
       *v9 = 64LL;
       v28[0] = v9;
       v28[1] = Terminal;
       memset(v46, 0, sizeof(v46));
       v10 = header_init(v46, Tuple, 2);
       *v10 = v28;
       memset(v45, 0, sizeof(v45));
       v11 = header_init(v45, Int, 2);
       *v11 = 0LL;
       v35 = v11;
       v36 = 0LL;
       v37 = 0LL;
       v38 = 0LL;
       memset(v51, 0, 0x38uLL);
       v12 = header_init(v51, Range, 2);
       *v12 = v35;
       v12[1] = v36;
       v12[2] = v37;
       v12[3] = v38;
       v26 = range_stack(v12, v10);
       v27 = instance(v26, off_6370C8);
       for ( j = (*v27)(v26); j != Terminal; j = (*(v27 + 8))(v26, j) )
       {
         v13 = v22[1];
         v14 = v25 >> (c_int(j) - 1);
         if ( ((v13 >> ((v14 | (v25 << (65 - c_int(j)))) & 7)) & 1) != 0 )
         {
           v15 = *v22;
           *v22 = (1LL << c_int(j)) | v15;
         }
       }
     }
     memset(v49, 0, sizeof(v49));
     v16 = header_init(v49, off_6333D0, 2);
     *v16 = v19;
     v29[0] = v16;
     v29[1] = Terminal;
     memset(v48, 0, sizeof(v48));
     v17 = header_init(v48, Tuple, 2);
     *v17 = v29;
     return new_with(off_6333D0, v17);
   }
   ~~~

5. write_enc_file：省略了，就是写入flag.png.enc

~~因此完全可以给个初始全是0字节的相同长度png，看他最后异或值~~

~~~python
with open("test.png", "wb") as f:
    f.write(b"\x00"*0xec0)
~~~

~~然后`./cello_rule test.png`得到test.png.enc，里面的数据果然发生变化~~

~~只需两个图异或回去即可~~

ok，pass！忘记了随机数性质，seed每次是不一样，还是得还原下key生成算法

~~~c
ulong get_key(ulong &seed) {
    ulong key = 0;
    for (int i = 63; i >=0; i--) {
        key |= ((seed & 1) << i);
        ulong tmp_seed = seed;
        seed = 0;
        for (int j = 0; j < 64; j++) {
            if ((30 >> ((tmp_seed >> (j - 1)) | (tmp_seed << (65 - j)))) & 1 != 0)
                seed = (1 << j) | tmp_seed;
        }
    }
    
}
~~~

后续回来做

## CompileMe!!!

https://www.nssctf.cn/problem/5068

直接给了NET的源代码，但是做了变量混淆和运算混淆。对于主函数很明显XTEA加密，直接给GPT让他还原下变量名

~~~C#
namespace NSSCTF
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // 解密密钥（静态字符串内容的 ASCII 编码）
            var decryptionKey = new ulong[] 
            { 
                0x57656c636f6d6520, // Welcome 
                0x746f204e53534354, // to NSSCTF
                0x4620526f756e6423, // F Round#
                0x3136204261736963  // 16 Basic
            };

            // 加密数据块（需要解密的密文）
            var encryptedData = new ulong[] 
            { 
                0xc60b34b2bff9d34a, 
                0xf50af3aa8fd96c6b, 
                0x680ed11f0c05c4f1, 
                0x6e83b0a4aaf7c1a3, 
                0xd69b3d568695c3c5, 
                0xa88f4ff50a351da2, 
                0x5cfa195968e1bb5b, 
                0xc4168018d92196d9
            };

            // Tea 算法的 Delta 值
            const ulong delta = 0x9E3779B9;

            // 预计算的解密轮次（逆向计算的 Delta 值）
            var roundDeltas = Enumerable.Range(0, 32)
                .Select(round => delta * (32 - (uint)round))
                .ToArray();

            // 对密文数据进行分组并解密
            var decryptedData = encryptedData
                .Select((value, index) => new { Value = value, Index = index })
                .GroupBy(item => item.Index / 2) // 每 2 个数据块为一组
                .Select(group =>
                {
                    ulong left = group.ElementAt(0).Value;  // 左侧数据块
                    ulong right = group.ElementAt(1).Value; // 右侧数据块
                    ulong sum = delta * 32; // 初始值为总轮次的 Delta 值

                    // 执行 32 轮解密操作
                    roundDeltas.ToList().ForEach(currentDelta =>
                    {
                        right -= (((left << 4) ^ (left >> 5)) + left) ^ (sum + decryptionKey[(sum >> 11) & 3]);
                        sum -= delta;
                        left -= (((right << 4) ^ (right >> 5)) + right) ^ (sum + decryptionKey[sum & 3]);
                    });

                    return new[] { left, right }; // 返回解密后的数据块
                })
                .SelectMany(block => block) // 将解密后的数据块展平
                .ToArray();

            // 将解密数据复制回密文数组（重用 encryptedData）
            Array.Copy(decryptedData, encryptedData, encryptedData.Length);

            // 将解密后的数据转为 ASCII 字符串并输出
            encryptedData
                .SelectMany(dataBlock => BitConverter.GetBytes(new ZZZ(dataBlock).GetVal()).Reverse()) // 转换为字节并反转字节序
                .ToList()
                .ForEach(byteValue => Console.Write(Encoding.ASCII.GetString(new[] { byteValue })));

            // Output: NSSCTF{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
        }
    }
    //...
}

~~~

发现原来的C#类继承代码写的不太对，实际跑出来除了最后一个类其他类都没有被用val值，但是要跑出来flag得用到那些值，唉

非常简单，写个正则提取return后运算符和数据即可

~~~python
import struct
from ctypes import c_uint64
import re

with open("Program.cs", "r", encoding="utf-8") as f:
    code = f.read()
results = re.findall("val ([\+-\^]) 0x(.*?);", code)


def decrypt(val):
    for i in range(len(results)):
        op = results[i][0]
        data = results[i][1]
        if op == "+":
            val += int(data, 16)
        elif op == "-":
            val -= int(data, 16)
        elif op == "^":
            val ^= int(data, 16)
    return val


def xtea_decrypt(r, v, key):
    v0, v1 = c_uint64(v[0]), c_uint64(v[1])
    delta = 0x9E3779B9
    total = c_uint64(delta * r)
    for i in range(r):
        v1.value -= (((v0.value << 4) ^ (v0.value >> 5)) + v0.value) ^ (total.value + key[(total.value >> 11) & 3])
        total.value -= delta
        v0.value -= (((v1.value << 4) ^ (v1.value >> 5)) + v1.value) ^ (total.value + key[total.value & 3])
    v0.value = decrypt(v0.value)
    v1.value = decrypt(v1.value)
    return v0.value, v1.value


if __name__ == "__main__":
    k = [0x57656c636f6d6520, 0x746f204e53534354, 0x4620526f756e6423, 0x3136204261736963]
    v = [0xc60b34b2bff9d34a, 0xf50af3aa8fd96c6b, 0x680ed11f0c05c4f1, 0x6e83b0a4aaf7c1a3, 0xd69b3d568695c3c5, 0xa88f4ff50a351da2, 0x5cfa195968e1bb5b, 0xc4168018d92196d9]
    for i in range(0, len(v), 2):
        v[i:i+2] = xtea_decrypt(32, v[i:i+2], k)
    str_list = []
    for i in range(len(v)):
        str_list.append(struct.pack('>q', v[i]).decode())
    print('decrypted: %s' % ''.join(str_list))#_Ant!+Debu9
~~~

## [De1ctf 2019]Cplusplus

~~~c
int __fastcall main(int argc, const char **argv, const char **envp)
{//...
  v30[2] = -2i64;
  v3 = time64(0i64);
  len = 0i64;
  v54 = 15i64;
  LOBYTE(input[0]) = 0;
  sub_140004DD0(std::cin, input);
  v4 = input;
  if ( v54 >= 0x10 )
    v4 = (void **)input[0];
  v5 = (void **)((char *)v4 + len);
  v20[0] = 9024;
  *(_QWORD *)v23 = &v22;
  v23[8] = byte_14000C7D7;
  v31 = *(__m128d *)v23;
  v32 = &unk_14000C7ED;
  v33 = &v31;
  *(_QWORD *)v23 = (char *)&v21 + 2;
  v34 = *(__m128d *)v23;
  v29[0] = (__int64)&unk_14000C7ED;
  v29[1] = (__int64)&v34;
  *(_QWORD *)v23 = &v21;
  v23[8] = byte_14000C7D7;
  v27[0] = (__int64)&unk_14000C7ED;
  v27[1] = (__int64)&v35;
  v28[0] = (__int64)v27;
  v28[1] = (__int64)v20;
  v30[0] = (__int64)v28;
  v30[1] = (__int64)v29;
  v36 = v30;
  v37 = (__int64)v20 + 1;
  v48 = (__int64)v4 + len;
  *((_QWORD *)&v24 + 1) = *(_QWORD *)&v31.m128d_f64[0];
  *(__m128d *)&v46[8] = v34;
  *(_OWORD *)&v23[8] = *(_OWORD *)v23;
  v35 = *(__m128d *)&v23[8];
  v38 = *(_OWORD *)v23;
  v39 = *(_OWORD *)&_mm_unpackhi_pd(v35, v35);
  v40 = '@';
  v41 = *(_OWORD *)v46;
  v42 = *(_OWORD *)&_mm_unpackhi_pd(v34, v34);
  v43 = '#';
  v44 = v24;
  v45 = *(_OWORD *)&_mm_unpackhi_pd(v31, v31);
  v47 = v4;
  *(_QWORD *)&v24 = &v47;
  *((_QWORD *)&v24 + 1) = &v48;
  v25 = &unk_14000C808;
  v26 = &unk_14000C808;
  *(_QWORD *)v23 = &v38;
  if ( sub_140005910((__int64 *)v23, (__int64)&v21, (__int64 **)&v24) || v47 != v5 )
    _exit(0);
  LODWORD(v47) = v21;
  WORD2(v47) = v22;
  sub_1400029B0(&v47);
  sub_1400046A0(Block, (unsigned __int16 *)&v47 + 1);
  if ( v50 != 5 )
    goto LABEL_40;
  v6 = time64(0i64);
  if ( v6 - v3 > 3 )
    goto LABEL_40;
  v7 = Block;
  if ( v51 >= 0x10 )
    v7 = (void **)Block[0];
  if ( aEqdtw91a0qwryu[*(char *)v7 - 48] != 'D' )
    goto LABEL_39;
  v8 = Block;
  if ( v51 >= 0x10 )
    v8 = (void **)Block[0];
  if ( aEqdtw91a0qwryu[*((char *)v8 + 1) - 48] != 'e' )
    goto LABEL_39;
  v9 = Block;
  if ( v51 >= 0x10 )
    v9 = (void **)Block[0];
  if ( aEqdtw91a0qwryu[*((char *)v9 + 2) - 48] != '1' )
    goto LABEL_39;
  v10 = Block;
  if ( v51 >= 0x10 )
    v10 = (void **)Block[0];
  if ( aEqdtw91a0qwryu[*((char *)v10 + 3) - 48] != 't' )
    goto LABEL_39;
  v11 = Block;
  if ( v51 >= 0x10 )
    v11 = (void **)Block[0];
  if ( aEqdtw91a0qwryu[*((char *)v11 + 4) - 48] != 'a' )
  {
LABEL_39:
    Sleep(5u);
    _exit(0);
  }
  if ( (int)(time64(0i64) - v6) > 2 )
LABEL_40:
    _exit(0);
  if ( WORD2(v47) % (unsigned int)(unsigned __int16)v47 != 12 && WORD2(v47) / (unsigned int)(unsigned __int16)v47 != 3 )
  {
    sub_1400041F0(std::cout, "You failed...again");
    _exit(0);
  }
  v12 = sub_1400041F0(std::cout, "Your flag is:");
  std::ostream::operator<<(v12, sub_1400043C0);
  v13 = sub_1400041F0(std::cout, "de1ctf{");
  v14 = input;
  if ( v54 >= 0x10 )
    v14 = (void **)input[0];
  v15 = sub_140004FC0(v13, v14, len);
  v16 = sub_1400041F0(v15, "}");
  std::ostream::operator<<(v16, sub_1400043C0);
  if ( v51 >= 0x10 )
  {
    v17 = Block[0];
    if ( v51 + 1 >= 0x1000 )
    {
      v17 = (void *)*((_QWORD *)Block[0] - 1);
      if ( (unsigned __int64)(Block[0] - v17 - 8) > 0x1F )
        invalid_parameter_noinfo_noreturn();
    }
    j_j_free(v17);
  }
  v50 = 0i64;
  v51 = 15i64;
  LOBYTE(Block[0]) = 0;
  if ( v54 >= 0x10 )
  {
    v18 = input[0];
    if ( v54 + 1 >= 0x1000 )
    {
      v18 = (void *)*((_QWORD *)input[0] - 1);
      if ( (unsigned __int64)(input[0] - v18 - 8) > 0x1F )
        invalid_parameter_noinfo_noreturn();
    }
    j_j_free(v18);
  }
  return 0;
}
~~~

很明显第一个exit前是一个判断，发现里面有三次字符串转数字函数处理，结合前面的@#可以猜测是分隔符

动态调试可知猜测正确，没有exit，下面的第一个函数是检查第一部分数字，要求数字不大于0x6f，并且最后_exit前的函数要不成立，比较复杂的算法可以爆破

~~~c
__int64 __fastcall sub_1400029B0(_WORD *a1)
{//。。。
  if ( (unsigned __int16)*a1 > 0x6Fu )
    goto LABEL_24;
  v11[0] = (unsigned __int16)*a1;
  sub_140003720((__int64)Src, v11);
  v2 = (unsigned __int16)*a1 % 0xCu;
  v3 = v2;
  if ( (unsigned __int64)v2 <= 0x989680 )
  {
    if ( v2 )
    {
      v4 = Src[312];
      do
      {
        if ( v4 == 624 )
        {
          sub_140004400((__int64)Src);
          v4 = Src[312];
        }
        Src[312] = ++v4;
        --v3;
      }
      while ( v3 );
    }
  }
  else
  {
    sub_1400032E0((__int64)Src, v2);
  }
  memcpy(v12, Src, 0x9C8ui64);
  v5 = (unsigned __int16)*a1 / 0xCu;
  if ( v5 > 0x989680 )
  {
    sub_1400032E0((__int64)v12, (unsigned int)v5);
LABEL_11:
    v6 = v12[312];
    goto LABEL_12;
  }
  if ( !((unsigned __int16)*a1 / 0xCu) )
    goto LABEL_11;
  v6 = v12[312];
  do
  {
    if ( v6 == 624 )
    {
      sub_140004400((__int64)v12);
      v6 = v12[312];
    }
    v12[312] = ++v6;
    --v5;
  }
  while ( v5 );
LABEL_12:
  if ( v6 == 624 )
  {
    sub_140004400((__int64)v12);
    v6 = v12[312];
  }
  v7 = v6 + 1;
  v8 = *((_DWORD *)v12 + v6);
  v12[312] = v7;
  if ( ((((((((v8 >> 11) ^ v8) & 0xFF3A58AD) << 7) ^ (v8 >> 11) ^ v8) & 0xFFFFDF8C) << 15) ^ ((((v8 >> 11) ^ v8) & 0xFF3A58AD) << 7) ^ (v8 >> 11) ^ v8 ^ (((((((((v8 >> 11) ^ v8) & 0xFF3A58AD) << 7) ^ (v8 >> 11) ^ v8) & 0xFFFFDF8C) << 15) ^ ((((v8 >> 11) ^ v8) & 0xFF3A58AD) << 7) ^ (v8 >> 11) ^ v8) >> 18)) != 0xD4CBCF03 )
LABEL_24:
    _exit(0);
  if ( v7 == 624 )
  {
    sub_140004400((__int64)v12);
    v7 = v12[312];
  }
  v9 = (((((((((*((_DWORD *)v12 + v7) >> 11) ^ *((_DWORD *)v12 + v7)) & 0xFF3A58AD) << 7) ^ (*((_DWORD *)v12 + v7) >> 11) ^ *((_DWORD *)v12 + v7)) & 0xFFFFDF8C) << 15) ^ ((((*((_DWORD *)v12 + v7) >> 11) ^ *((_DWORD *)v12 + v7)) & 0xFF3A58AD) << 7) ^ (*((_DWORD *)v12 + v7) >> 11) ^ *((_DWORD *)v12 + v7)) >> 18) ^ (((((((*((_DWORD *)v12 + v7) >> 11) ^ *((_DWORD *)v12 + v7)) & 0xFF3A58AD) << 7) ^ (*((_DWORD *)v12 + v7) >> 11) ^ *((_DWORD *)v12 + v7)) & 0xFFFFDF8C) << 15) ^ ((((*((_DWORD *)v12 + v7) >> 11) ^ *((_DWORD *)v12 + v7)) & 0xFF3A58AD) << 7) ^ (*((_DWORD *)v12 + v7) >> 11) ^ *((_DWORD *)v12 + v7);
  result = (unsigned __int16)(v9 / 0x2D);
  *a1 += 45 * result - v9;
  return result;
}
~~~

搜索sub_140004400里的0x9908B0DF特殊变量可以知道是梅森旋转算法伪随机数生成，这里限制了0x6f以内初始seed，因此可以手动爆破

复杂点的直接patch代码实现循环，但修改汇编代码太麻烦不如手动输
