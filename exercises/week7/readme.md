# Week 7（2024.10.28-2024.11.3）

## 刷题的知识点

1. 注意python下标+-1
2. try-catch异常 ida反编译可能没显示全去汇编代码里看

## [柏鹭杯 2021]baby_go

md想多了，go文件里同时给了加密解密的算法，所以我在调用加密算法的时候修改跳转函数地址（传入参数一样）直接跳到了解密代码，跑出了flag

结果看wp有直接加密对换文件就跑出来代码了，合着根本不用分析代码，笑cry

以后碰到类似先这样试↑

**ok接下来练习下go语言逆向**

## [HGAME 2023 week4]shellcode

go语言编写的恶意加密shellcode，隐藏了shellcode到很长的base64字符串（**ida显示不全，双击字符串查看！！！**），解密后写入文件可以直接ida64分析函数

可以看到tea加密，直接解密即可

~~~python
# from base64 import b64decode
#
# base64_c = "VUiD7FBIjWwkIEiJTUBIi0VAiwCJRQC4BAAAAEgDRUCLAIlFBMdFCAAAAADHRQwj782rx0UQFgAAAMdFFCEAAADHRRgsAAAAx0UcNwAAAMdFIAAAAACLRSCD+CBzWotFDANFCIlFCItFBMHgBANFEItVCANVBDPCi1UEweoFA1UUM8IDRQCJRQCLRQDB4AQDRRiLVQgDVQAzwotVAMHqBQNVHDPCA0UEiUUEuAEAAAADRSCJRSDrnkiLRUCLVQCJELgEAAAASANFQItVBIkQSI1lMF3D"
# content = b64decode(base64_c.encode())
# print(content)
# with open("shellcode", "wb") as f:
#     f.write(content)
import struct
from ctypes import c_uint32
from Crypto.Util.number import bytes_to_long

def tea_decrypt(r, v, key, delta):
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    total = c_uint32(-delta * r)
    for i in range(r):
        v1.value -= ((v0.value << 4) + key[2]) ^ (v0.value + total.value) ^ ((v0.value >> 5) + key[3])
        v0.value -= ((v1.value << 4) + key[0]) ^ (v1.value + total.value) ^ ((v1.value >> 5) + key[1])
        total.value += delta
    return v0.value, v1.value

k = [22, 33, 44, 55]
with open("outputdir/flag.enc", "rb") as f:
    content = f.read()
v = []
for i in range(0, len(content), 4):
    v.append(bytes_to_long(content[i:i+4][::-1]))
delta = 0x543210DD
for i in range(0, len(v), 2):
    v[i:i+2] = tea_decrypt(32, v[i:i+2], k, delta)
str_list = []
for i in range(len(v)):
    str_list.append(struct.pack('<I', v[i]).decode())
print('decrypted: %s' % ''.join(str_list))
~~~

这道题大概了解了go语言逆向的要点：

1. 找main\_main
2. 找关键函数（这个调用是没法直接看出来的，要么动态调试，要么直接硬分析）
3. 里面很多系统调用函数关注下，可能代码藏在要解密的字符串里

## [长安杯 2021学生组]snake

这道题做了优化所以代码比较复杂，出现很多\_mm_load_si128这种api

直接定位flag打印的位置，发现其值是在0xDEADBEEFDEADBEEF基础上不断+grid_mats的值

~~~c
__int64 calc_flag()
{
  __m128i *v0; // rcx
  unsigned __int64 v1; // r12
  char *m128i_i8; // rdx
  __m128i *v3; // rax
  __m128i v4; // xmm0

  v0 = (__m128i *)&grid_mats;
  v1 = 0xDEADBEEFDEADBEEFLL;
  m128i_i8 = (char *)&grid_mats + 400;
  do
  {
    v3 = v0;
    v4 = 0LL;
    do
      v4 = _mm_add_epi64(v4, *v3++);
    while ( v3 != (__m128i *)m128i_i8 );
    v0 += 25;
    v1 += _mm_add_epi64(v4, _mm_srli_si128(v4, 8)).m128i_u64[0];
    m128i_i8 = v3[25].m128i_i8;
  }
  while ( &v3[25] != (__m128i *)((char *)&grid_mats + 20400) );
  __printf_chk(1LL, "\x1B[%d;%dH", 6LL, 32LL);
  __printf_chk(1LL, "\x1B[%d;%dm", 1LL, 31LL);
  return __printf_chk(1LL, "The flag is: flag{%lu}\n", v1);
}
~~~

往前找grid_mats赋值的地方

后面没时间钻研了，具体思路就是patch代码，使得游戏加速循环200次得到flag

## [NSSRound#22 Basic]Go!Go!Go!

看到关键函数，在Go.exe里找到资源文件

~~~c
LPVOID __fastcall sub_140001030(unsigned __int16 a1)
{
  HMODULE hModule; // [rsp+20h] [rbp+0h]
  CHAR Type[8]; // [rsp+28h] [rbp+8h] BYREF
  HRSRC hResInfo; // [rsp+30h] [rbp+10h]
  HGLOBAL hResData; // [rsp+38h] [rbp+18h]
  LPVOID v6; // [rsp+40h] [rbp+20h]

  hModule = GetModuleHandleW(0i64);
  strcpy(Type, "gOG0");
  hResInfo = FindResourceA(hModule, (LPCSTR)a1, Type);
  if ( !hResInfo )
    return 0i64;
  hResData = LoadResource(hModule, hResInfo);
  if ( !hResData )
    return 0i64;
  v6 = LockResource(hResData);
  if ( !v6 )
    return 0i64;
  FreeResource(hResData);
  return v6;
}
~~~

发现是MZ开头直接导出得到Go语言的加密exe

直接找main开头的函数：

main_main：先是main_Function1通过哈希检查输入的两个key，然后是输入flag，main_Function2来检查发现rc4特征

本来以为第一个函数可以绕过，结果发现返回的结果疑似作为key给了第二个函数，因此main_Function1的md5、sha256必须爆破（看了wp才知道一般爆破方法不行，得hashcat）

~~~
./hashcat.exe -a 3 -m 0 b098cacb2d43b882ef9a83168d13c3a7 ?a?a?a?a?a?a
./hashcat.exe -a 3 -m 1400 c32a69f4609191a2c3e6dbe2effc329bff20617230853462e8745f2c058bec2f ?a?a?a?a?a?a
~~~

貌似得有GPU，分别得到`G0@K3y`和`n3SC1f`，拼起来就是rc4的密钥，但是rc4是魔改了，多异或了一个下标i

## [网鼎杯 2022 青龙组]Handmake

不是go二进制文件逆向，而是源代码逆向

* `Input the first function, which has 6 parameters and the third named gLIhR:`找到`ZlXDJkH3OZN4Mayd`
* `Input the second function, which has 3 callers and invokes the function named cHZv5op8rOmlAkb6:`找到`WcKCdRGFuj4WoTPg`

按照处理逻辑得到

## [天翼杯 2021]bbgo

查到了[crc16校验](https://blog.csdn.net/renlonggg/article/details/119734367)，不知道为什么yara search插件失效没检测出来这个算法

接下来不会，搁置

找到了全网唯一[wp](https://www.anquanke.com/post/id/254670)。。。

## [MoeCTF 2021]time2go

很简单，直接就能打印flag，因为检测运行时间可以把每次循环里sleep的时间patch为0

## [NSSRound#17 Basic]snake

同上，本来想着分析下贪吃蛇怎么算玩完一局的逻辑，但看了一圈下来逻辑写的太多，遂直接patch修改使得游戏直接结束，patch的主要有两点

1. 一局游戏里的循环-snake_pkg_app_Run直接patch成 while 0
2. 游戏需要打十局，十局完成后会有一个判断`if ( i == 10 && qword_939E78 == 400 )`，这里qword_939E78 需要修改为!=400

patch完直接运行就会打印flag

## [GKCTF 2021]Crash

很简单，3des+base64+hash爆破

## GO逆向总结

简单题一般不会混淆IAT，可以直接找main开头的函数，难题通常得手动sub函数里去找关键加密函数。通常都会用到api，多查下就好

接下来学下VM相关题目



