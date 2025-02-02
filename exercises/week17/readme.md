# Week 17（2025.1.6-2025.1.13）

## [巅峰极客 2021]baby_maze

https://www.nssctf.cn/problem/1162

很搞人，头次见到把迷宫写成这么复杂的逻辑，超级多的函数检查迷宫正确路径，研究了一晚上api结果写的逻辑过于复杂，主要是switch的jmptable跳转点不好确定，搜了很多wp才发现一个完全使用idc脚本的[简洁代码](https://s1lenc3-chenmo.github.io/2021/08/03/%E5%B7%85%E5%B3%B0%E6%9E%81%E5%AE%A22021%E9%80%86%E5%90%91wp/)，利用了调用函数上一个指令注释里有case值，我自己也实现了个读取switch值的方法

~~~python
from hashlib import md5

# 用于记录访问过的函数地址
visited = set()

def extract_case_values(addr):
    switch = GetCommentEx(addr-5, True)
    return chr(int(switch.split()[-1]))
    

def dfs(start_ea, call_paths):
    """
    深度优先搜索DFS，用于从函数start_ea递归地找到所有调用的函数。
    """
    if start_ea in visited:
        return
    visited.add(start_ea)
    xref_addrs = []
    for i in CodeRefsTo(start_ea,False):
        addr = idc.get_func_attr(i, FUNCATTR_START)
        if addr == 0x40180E:
            s = ""
            for j in range(len(call_paths)-1, -1, -1):
                s += extract_case_values(call_paths[j])
            s = "s"+s
            print(s)
            return
        dfs(addr, call_paths+[i])
    for addr in xref_addrs:
        dfs(addr, call_paths)


def main():
    target_func_ea = 0x54DE35
    dfs(target_func_ea, [])

if __name__ == '__main__':
    main()
~~~

打印出来的s再md5即可得到答案

## [CISCN 2022 初赛]babycode

https://www.nssctf.cn/problem/2342

mruby字节码逆向，需要下载对应版本mruby3.1.0然后提取[字节码](https://silentworlds.info/2019/08/09/post-814/)

字节码不少只能一个个函数分析，一眼扫过去很明显tea类加密，需要确定具体

主函数

~~~ruby
irep 0x55d98ae710e0 nregs=5 nlocals=2 pools=1 syms=5 reps=2 ilen=55
local variable names:
  R1:p
      000 LOADNIL	R2		
      002 LOADNIL	R3		
      004 CLASS		R2	:Crypt
      007 EXEC		R2	I(0:0x55d98ae71190)
      010 TCLASS	R2		
      012 METHOD	R3	I(1:0x55d98ae71990)
      015 DEF		R2	:check
      018 SSEND		R2	:gets	n=0 (0x00)
      022 SEND		R2	:chomp	n=0 (0x00)
      026 MOVE		R1	R2		; R1:p
      029 MOVE		R3	R1		; R1:p
      032 SSEND		R2	:check	n=1 (0x01)
      036 JMPNOT	R2	050	
      040 STRING	R3	L(0)	; yes
      043 SSEND		R2	:puts	n=1 (0x01)
      047 JMP		052
      050 LOADNIL	R2		
      052 RETURN	R2		
      054 STOP
~~~

类CIPHER

~~~ruby
irep 0x55d98ae71190 nregs=3 nlocals=1 pools=0 syms=1 reps=1 ilen=12
      000 LOADNIL	R1		
      002 LOADNIL	R2		
      004 CLASS		R1	:CIPHER
      007 EXEC		R1	I(0:0x55d98ae71260)
      010 RETURN	R1		
~~~

类里函数

~~~ruby
irep 0x55d98ae71260 nregs=3 nlocals=1 pools=0 syms=6 reps=4 ilen=55
      000 LOADI32	R1	305419896	// XX=0x12345678
      006 SETCONST	XX	R1	
      009 LOADI		R1	16	
      012 SETCONST	YY	R1	 // YY=16
      015 LOADSELF	R1		
      017 SCLASS		R1	
      019 METHOD	R2	I(0:0x55d98ae713a0)
      022 DEF		R1	:encrypt
      025 TCLASS	R1		
      027 METHOD	R2	I(1:0x55d98ae71440) // 私有encrypt函数
      030 DEF		R1	:encrypt
      033 SSEND		R1	:private	n=0 (0x00)
      037 TCLASS	R1		
      039 METHOD	R2	I(2:0x55d98ae71760)
      042 DEF		R1	:to_key
      045 TCLASS	R1		
      047 METHOD	R2	I(3:0x55d98ae71830)
      050 DEF		R1	:enc_one
      053 RETURN	R1	
~~~

check函数里面首先有个循环异或，然后加密，然后和硬编码值比较

~~~ruby
irep 0x55d98ae71990 nregs=13 nlocals=8 pools=2 syms=7 reps=0 ilen=128
local variable names:
  R1:p
  R2:&  // 参数与局部变量的划分线
  R3:i
  R4:lst_ch
  R5:c
  R6:k
  R7:cipher_text
      000 ENTER		1:0:0:0:0:0:0 (0x40000)
      004 LOADI_0	R3			; R3:i  // i=0
      006 LOADI_0	R4			; R4:lst_ch  // lst_ch=0
      008 MOVE		R8	R3		; R3:i
      011 MOVE		R9	R1		; R1:p
      014 SEND		R9	:length	n=0 (0x00)
      018 LT		R8	R9   // 开始循环遍历字符串
      020 JMPNOT	R8	086	
      024 MOVE		R8	R1		; R1:p
      027 MOVE		R9	R3		; R3:i
      030 GETIDX	R8	R9  // R8=p[i]
      032 SEND		R8	:ord	n=0 (0x00)  // 取ascii值
      036 MOVE		R5	R8		; R5:c  // c=ord(p[i])
      039 MOVE		R8	R5		; R5:c
      042 MOVE		R9	R4		; R4:lst_ch
      045 SEND		R8	:^	n=1 (0x01)
      049 MOVE		R9	R3		; R3:i  // ^(i+1)
      052 ADDI		R9	1	
      055 SEND		R8	:^	n=1 (0x01)
      059 SEND		R8	:chr	n=0 (0x00)
      063 MOVE		R9	R1		; R1:p
      066 MOVE		R10	R3		; R3:i
      069 MOVE		R11	R8	
      072 SETIDX	R9	R10	R11  // p[i]=chr(ord(p[i])^lst_ch^(i+1))
      074 MOVE		R8	R5		; R5:c
      077 MOVE		R4	R8		; R4:lst_ch  // lst_ch=c
      080 ADDI		R3	1		; R3:i  // i++
      083 JMP		008
      086 STRING	R6	L(0)	; aaaassssddddffff	; R6:k
      089 GETCONST	R8	Crypt	
      092 GETMCNST	R8	R8::CIPHER	
      095 MOVE		R9	R1		; R1:p
      098 MOVE		R10	R6		; R6:k
      101 SEND		R8	:encrypt	n=2 (0x02)
      105 MOVE		R7	R8		; R7:cipher_text
      108 MOVE		R8	R7		; R7:cipher_text
      111 STRING	R9	L(1)	; f469358b7f165145116e127ad6105917bce5225d6d62a714c390c5ed93b22d8b6b102a8813488fdb
      114 EQ		R8	R9
      116 JMPNOT	R8	124	
      120 LOADT		R8		
      122 RETURN	R8		
      124 LOADF		R8		
      126 RETURN	R8	
~~~

开始加密，每8字节一组，每四字节转unsigned int

~~~ruby
irep 0x55d98ae71440 nregs=16 nlocals=11 pools=1 syms=8 reps=1 ilen=346
local variable names:
  R1:t
  R2:p
  R3:&
  R4:key
  R5:c
  R6:n
  R7:num1
  R8:num2
  R9:enum1
  R10:enum2
      000 ENTER		2:0:0:0:0:0:0 (0x80000)
      004 MOVE		R12	R2		; R2:p
      007 SSEND		R11	:to_key	n=1 (0x01)
      011 MOVE		R4	R11		; R4:key  // key=to_key(p)
      014 ARRAY		R5	R5	0	; R5:c  // c=[]
      017 LOADI_0	R6			; R6:n  // n=0
      019 MOVE		R11	R6		; R6:n
      022 MOVE		R12	R1		; R1:t
      025 SEND		R12	:length	n=0 (0x00)
      029 LT		R11	R12 // n<len(t)
      031 JMPNOT	R11	327	
      035 MOVE		R11	R1		; R1:t
      038 MOVE		R12	R6		; R6:n
      041 GETIDX	R11	R12  // t[n]
      043 SEND		R11	:ord	n=0 (0x00)  // ord(t[n])
      047 SEND		R11	:to_i	n=0 (0x00)  // to_i(ord(t[n]))
      051 LOADI		R12	24	
      054 SEND		R11	:<<	n=1 (0x01)  // 从这里开始左移24、16、8位并拼接，是每四位转成一个unsigned int
      058 MOVE		R7	R11		; R7:num1
      061 MOVE		R11	R7		; R7:num1
      064 MOVE		R12	R1		; R1:t
      067 MOVE		R13	R6		; R6:n
      070 ADDI		R13	1	
      073 GETIDX	R12	R13
      075 SEND		R12	:ord	n=0 (0x00)
      079 SEND		R12	:to_i	n=0 (0x00)
      083 LOADI		R13	16	
      086 SEND		R12	:<<	n=1 (0x01)
      090 ADD		R11	R12
      092 MOVE		R7	R11		; R7:num1
      095 MOVE		R11	R7		; R7:num1
      098 MOVE		R12	R1		; R1:t
      101 MOVE		R13	R6		; R6:n
      104 ADDI		R13	2	
      107 GETIDX	R12	R13
      109 SEND		R12	:ord	n=0 (0x00)
      113 SEND		R12	:to_i	n=0 (0x00)
      117 LOADI		R13	8	
      120 SEND		R12	:<<	n=1 (0x01)
      124 ADD		R11	R12
      126 MOVE		R7	R11		; R7:num1
      129 MOVE		R11	R7		; R7:num1
      132 MOVE		R12	R1		; R1:t
      135 MOVE		R13	R6		; R6:n
      138 ADDI		R13	3	
      141 GETIDX	R12	R13
      143 SEND		R12	:ord	n=0 (0x00)
      147 SEND		R12	:to_i	n=0 (0x00)
      151 ADD		R11	R12
      153 MOVE		R7	R11		; R7:num1
      156 MOVE		R11	R1		; R1:t
      159 MOVE		R12	R6		; R6:n
      162 ADDI		R12	4	
      165 GETIDX	R11	R12
      167 SEND		R11	:ord	n=0 (0x00)
      171 SEND		R11	:to_i	n=0 (0x00)
      175 LOADI		R12	24	
      178 SEND		R11	:<<	n=1 (0x01)
      182 MOVE		R8	R11		; R8:num2
      185 MOVE		R11	R8		; R8:num2
      188 MOVE		R12	R1		; R1:t
      191 MOVE		R13	R6		; R6:n
      194 ADDI		R13	5	
      197 GETIDX	R12	R13
      199 SEND		R12	:ord	n=0 (0x00)
      203 SEND		R12	:to_i	n=0 (0x00)
      207 LOADI		R13	16	
      210 SEND		R12	:<<	n=1 (0x01)
      214 ADD		R11	R12
      216 MOVE		R8	R11		; R8:num2
      219 MOVE		R11	R8		; R8:num2
      222 MOVE		R12	R1		; R1:t
      225 MOVE		R13	R6		; R6:n
      228 ADDI		R13	6	
      231 GETIDX	R12	R13
      233 SEND		R12	:ord	n=0 (0x00)
      237 SEND		R12	:to_i	n=0 (0x00)
      241 LOADI		R13	8	
      244 SEND		R12	:<<	n=1 (0x01)
      248 ADD		R11	R12
      250 MOVE		R8	R11		; R8:num2
      253 MOVE		R11	R8		; R8:num2
      256 MOVE		R12	R1		; R1:t
      259 MOVE		R13	R6		; R6:n
      262 ADDI		R13	7	
      265 GETIDX	R12	R13
      267 SEND		R12	:ord	n=0 (0x00)
      271 SEND		R12	:to_i	n=0 (0x00)
      275 ADD		R11	R12
      277 MOVE		R8	R11		; R8:num2
      280 MOVE		R12	R7		; R7:num1
      283 MOVE		R13	R8		; R8:num2
      286 MOVE		R14	R4		; R4:key
      289 SSEND		R11	:enc_one	n=3 (0x03)  // enc_one(num1,num2,key)
      293 AREF		R9	R11	0	; R9:enum1
      297 AREF		R10	R11	1	; R10:enum2
      301 MOVE		R11	R5		; R5:c
      304 MOVE		R12	R9		; R9:enum1
      307 SEND		R11	:<<	n=1 (0x01)
      311 MOVE		R11	R5		; R5:c
      314 MOVE		R12	R10		; R10:enum2
      317 SEND		R11	:<<	n=1 (0x01)
      321 ADDI		R6	8		; R6:n  // n+=8，8个字节一组enc_one加密一次
      324 JMP		019
      327 MOVE		R11	R5		; R5:c
      330 BLOCK		R12	I(0:0x55d98ae71690)
      333 SENDB		R11	:collect	n=0 (0x00)
      337 STRING	R12	L(0)	; 
      340 SEND		R11	:join	n=1 (0x01)
      344 RETURN	R11
~~~

进入加密核心函数

~~~ruby
irep 0x55d98ae71830 nregs=11 nlocals=8 pools=0 syms=2 reps=1 ilen=42
local variable names:
  R1:num1
  R2:num2
  R3:key
  R4:&
  R5:y
  R6:z
  R7:s
      000 ENTER		3:0:0:0:0:0:0 (0xc0000)
      004 MOVE		R8	R1		; R1:num1
      007 MOVE		R9	R2		; R2:num2
      010 LOADI_0	R10		
      012 MOVE		R5	R8		; R5:y  // y=num1
      015 MOVE		R6	R9		; R6:z  // z=num2
      018 MOVE		R7	R10		; R7:s  // s=0
      021 GETCONST	R8	YY	// 16
      024 BLOCK		R9	I(0:0x55d98ae71900) // R5、R6、R7、R8
      027 SENDB		R8	:times	n=0 (0x00)   // 循环R8即16次
      031 MOVE		R8	R5		; R5:y
      034 MOVE		R9	R6		; R6:z
      037 ARRAY		R8	R8	2
      040 RETURN	R8		// return [y,z]
~~~

大循环16次里面的特殊值确定是XTEA加密且delta值为

~~~ruby
irep 0x55d98ae71900 nregs=10 nlocals=3 pools=1 syms=5 reps=0 ilen=186
local variable names:
  R1:i
  R2:&
      000 ENTER		1:0:0:0:0:0:0 (0x40000)
      004 GETUPVAR	R3	5	0	 // R3=R5即R3=num1
      008 GETUPVAR	R4	6	0	 // R4=R6即R4=num2
      012 LOADI_3	R5	// R5=3	
      014 SEND		R4	:<<	n=1 (0x01) // num2<<3
      018 GETUPVAR	R5	6	0  // R5=R6即R5=num2
      022 LOADI_5	R6	// R6=5	
      024 SEND		R5	:>>	n=1 (0x01)  // num2>>5,到这里基本确定是tea类
      028 SEND		R4	:^	n=1 (0x01)  // (num2<<3)^(num2>>5)
      032 GETUPVAR	R5	6	0  // R5=R6即R5=num2
      036 ADD		R4	R5  // num2+(num2<<3)^(num2>>5)
      038 GETUPVAR	R5	7	0	
      042 GETUPVAR	R6	3	0	
      046 GETUPVAR	R7	7	0	
      050 LOADI		R8	11  // 确定xtea！！后面不用看了都会了	
      053 SEND		R7	:>>	n=1 (0x01)
      057 ADDI		R7	1	
      060 LOADI_3	R8		
      062 SEND		R7	:&	n=1 (0x01)
      066 GETIDX	R6	R7
      068 ADD		R5	R6
      070 SEND		R4	:^	n=1 (0x01)
      074 ADD		R3	R4
      076 SETUPVAR	R3	5	0	
      080 LOADL		R4	L(0)	; 4294967295
      083 SEND		R3	:&	n=1 (0x01)
      087 SETUPVAR	R3	5	0	
      091 GETUPVAR	R3	7	0	
      095 GETCONST	R4	XX	
      098 ADD		R3	R4
      100 SETUPVAR	R3	7	0	
      104 GETUPVAR	R3	6	0	
      108 GETUPVAR	R4	5	0	
      112 LOADI_3	R5		
      114 SEND		R4	:<<	n=1 (0x01)
      118 GETUPVAR	R5	5	0	
      122 LOADI_5	R6		
      124 SEND		R5	:>>	n=1 (0x01)
      128 SEND		R4	:^	n=1 (0x01)
      132 GETUPVAR	R5	5	0	
      136 ADD		R4	R5
      138 GETUPVAR	R5	7	0	
      142 GETUPVAR	R6	3	0	
      146 GETUPVAR	R7	7	0	
      150 ADDI		R7	1	
      153 LOADI_3	R8		
      155 SEND		R7	:&	n=1 (0x01)
      159 GETIDX	R6	R7
      161 ADD		R5	R6
      163 SEND		R4	:^	n=1 (0x01)
      167 ADD		R3	R4
      169 SETUPVAR	R3	6	0	
      173 LOADL		R4	L(0)	; 4294967295
      176 SEND		R3	:&	n=1 (0x01)
      180 SETUPVAR	R3	6	0	
      184 RETURN	R3
~~~

ok全部搞定，写脚本，写的过程中发现魔改还是比较多的以后还是一点点还原吧

~~~python
import struct
from ctypes import c_uint32


def xtea_encrypt(r, v, key):
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    delta = 0x9e3779b9
    total = c_uint32(0)
    for i in range(r):
        v0.value += (((v1.value << 4) ^ (v1.value >> 5)) + v1.value) ^ (total.value + key[total.value & 3])
        total.value += delta
        v1.value += (((v0.value << 4) ^ (v0.value >> 5)) + v0.value) ^ (total.value + key[(total.value >> 11) & 3])
    return v0.value, v1.value


def xtea_decrypt(r, v, key):
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    delta = 0x12345678
    total = c_uint32(delta * r)
    for i in range(r):
        v1.value -= (((v0.value << 3) ^ (v0.value >> 5)) + v0.value) ^ (total.value + key[total.value + 1 & 3])
        total.value -= delta
        v0.value -= (((v1.value << 3) ^ (v1.value >> 5)) + v1.value) ^ (total.value + key[((total.value >> 11)+1) & 3])
    return v0.value, v1.value


if __name__ == "__main__":
    k = b"aaaassssddddffff"
    k = [struct.unpack("<I", k[i:i+4])[0] for i in range(0, 16, 4)]
    v = bytes.fromhex("f469358b7f165145116e127ad6105917bce5225d6d62a714c390c5ed93b22d8b6b102a8813488fdb")
    v = [struct.unpack(">I", v[i:i+4])[0] for i in range(0, len(v), 4)]
    for i in range(0, len(v), 2):
        v[i:i+2] = xtea_decrypt(16, v[i:i+2], k)
    str_list = []
    for i in range(len(v)):
        str_list += list(struct.pack('>I', v[i]))
    lst_ch = 0
    for i in range(len(str_list)):
        str_list[i] ^= lst_ch ^ (i + 1)
        lst_ch = str_list[i]
    print("".join(map(chr, str_list)))

~~~

