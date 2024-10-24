# Week 5（2024.10.14-2024.10.21）

## [强网杯 2022] GameMaster

~~~c#
private static void Main(string[] args)
{
	ConfigurationManager.AppSettings.Set("microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck", "true");
    FileStream fileStream = File.OpenRead("gamemessage");
    int num = (int)fileStream.Length;
    Program.memory = new byte[num];
    fileStream.Position = 0L;
    fileStream.Read(Program.memory, 0, num);
    Console.Title = "♠ Blackjack Game" + new string(' ', 11) + "...Based on Konstantin Tarkus' code";
    Console.BufferWidth = (Console.WindowWidth = 70);
    Console.BufferHeight = (Console.WindowHeight = 26);
    Console.CursorVisible = false;
    ArrayList arrayList = new ArrayList();
    Game game = new Game();
    game.Player.BalanceChanged += Program.OnBalanceChanged;
    game.LastStateChanged += Program.OnLastStateChanged;
    game.AllowedActionsChanged += Program.OnAllowedActionsChanged;
    game.Dealer.Hand.Changed += Program.OnHandChanged;
    game.Player.Hand.Changed += Program.OnHandChanged;
    game.Play(20m, 5m);
    // ...
    case ConsoleKey.Escape:
        Program.verifyCode(arrayList, game);
        continue;
   // ... 		
}
~~~

File.OpenRead("gamemessage")读取文件到memory变量。检查可知Program.verifyCode(arrayList, game);里开始对memory有所利用

~~~c#
game.Player.Bet -= 22m;
for (int i = 0; i < Program.memory.Length; i++)
{
    byte[] array = Program.memory;
    int num = i;
    array[num] ^= 34;
}
Environment.SetEnvironmentVariable("AchivePoint1", game.Player.Balance.ToString());
~~~

首先是异或34，之后是aes加密

~~~c#
game.Player.Balance += 175m;
byte[] key = new byte[]
{
    66,
    114,
    97,
    105,
    110,
    115,
    116,
    111,
    114,
    109,
    105,
    110,
    103,
    33,
    33,
    33
};
ICryptoTransform cryptoTransform = new RijndaelManaged
{
    Key = key,
    Mode = CipherMode.ECB,
    Padding = PaddingMode.Zeros
}.CreateDecryptor();
Program.m = cryptoTransform.TransformFinalBlock(Program.memory, 0, Program.memory.Length);
Environment.SetEnvironmentVariable("AchivePoint2", game.Player.Balance.ToString());
~~~

python解密

~~~python
from Crypto.Cipher import AES

s = [66,
     114,
     97,
     105,
     110,
     115,
     116,
     111,
     114,
     109,
     105,
     110,
     103,
     33,
     33,
     33]
s = "".join(map(chr, s))
print(s)
aes = AES.new(s.encode(), AES.MODE_ECB)
with open("gamemessage", "rb") as f:
    data = f.read()
data = bytearray(data)
for i in range(len(data)):
    data[i] ^= 34
data = aes.decrypt(data)
print(data)
~~~

在数据里发现了`MZ`、`This program cannot be run in DOS mode`等字眼，可知里面包含了可执行文件，提取下

~~~python
with open("message", "wb") as f1:
    f1.write(data[data.index(b"MZ"):])
~~~

还是dnspy反编译得到如下代码

~~~c#
using System;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace T1Class
{
	// Token: 0x02000002 RID: 2
	public class T1
	{
		// Token: 0x06000001 RID: 1 RVA: 0x00002050 File Offset: 0x00000250
		private static void Check1(ulong x, ulong y, ulong z, byte[] KeyStream)
		{
			int num = -1;
			for (int i = 0; i < 320; i++)
			{
				x = (((x >> 29 ^ x >> 28 ^ x >> 25 ^ x >> 23) & 1UL) | x << 1);
				y = (((y >> 30 ^ y >> 27) & 1UL) | y << 1);
				z = (((z >> 31 ^ z >> 30 ^ z >> 29 ^ z >> 28 ^ z >> 26 ^ z >> 24) & 1UL) | z << 1);
				bool flag = i % 8 == 0;
				if (flag)
				{
					num++;
				}
				KeyStream[num] = (byte)((long)((long)KeyStream[num] << 1) | (long)((ulong)((uint)((z >> 32 & 1UL & (x >> 30 & 1UL)) ^ (((z >> 32 & 1UL) ^ 1UL) & (y >> 31 & 1UL))))));
			}
		}

		// Token: 0x06000002 RID: 2 RVA: 0x00002110 File Offset: 0x00000310
		private static void ParseKey(ulong[] L, byte[] Key)
		{
			for (int i = 0; i < 3; i++)
			{
				for (int j = 0; j < 4; j++)
				{
					Key[i * 4 + j] = (byte)(L[i] >> j * 8 & 255UL);
				}
			}
		}

		// Token: 0x06000003 RID: 3 RVA: 0x0000215C File Offset: 0x0000035C
		public T1()
		{
			try
			{
				string environmentVariable = Environment.GetEnvironmentVariable("AchivePoint1");
				string environmentVariable2 = Environment.GetEnvironmentVariable("AchivePoint2");
				string environmentVariable3 = Environment.GetEnvironmentVariable("AchivePoint3");
				bool flag = environmentVariable == null || environmentVariable2 == null || environmentVariable3 == null;
				if (!flag)
				{
					ulong num = ulong.Parse(environmentVariable);
					ulong num2 = ulong.Parse(environmentVariable2);
					ulong num3 = ulong.Parse(environmentVariable3);
					ulong[] array = new ulong[3];
					byte[] array2 = new byte[40];
					byte[] array3 = new byte[40];
					byte[] array4 = new byte[12];
					byte[] first = new byte[]
					{
						101,
						5,
						80,
						213,
						163,
						26,
						59,
						38,
						19,
						6,
						173,
						189,
						198,
						166,
						140,
						183,
						42,
						247,
						223,
						24,
						106,
						20,
						145,
						37,
						24,
						7,
						22,
						191,
						110,
						179,
						227,
						5,
						62,
						9,
						13,
						17,
						65,
						22,
						37,
						5
					};
					byte[] array5 = new byte[]
					{
						60,
						100,
						36,
						86,
						51,
						251,
						167,
						108,
						116,
						245,
						207,
						223,
						40,
						103,
						34,
						62,
						22,
						251,
						227
					};
					array[0] = num;
					array[1] = num2;
					array[2] = num3;
					T1.Check1(array[0], array[1], array[2], array2);
					bool flag2 = first.SequenceEqual(array2);
					if (flag2)
					{
						T1.ParseKey(array, array4);
						for (int i = 0; i < array5.Length; i++)
						{
							array5[i] ^= array4[i % array4.Length];
						}
						MessageBox.Show("flag{" + Encoding.Default.GetString(array5) + "}", "Congratulations!", MessageBoxButtons.OK);
					}
				}
			}
			catch (Exception)
			{
			}
		}
	}
}
~~~

首先求解T1.Check1，得到array三个数，需要用到z3的比特计算

~~~python
from z3 import BitVec, sat, Solver

s = Solver()
x = BitVec("x", 64)
y = BitVec("y", 64)
z = BitVec("z", 64)
KeyStream = [BitVec(f"KeyStream{i}", 64) for i in range(40)]
num = -1
for i in range(120):
    x = (((x >> 29 ^ x >> 28 ^ x >> 25 ^ x >> 23) & 1) | x << 1)
    y = (((y >> 30 ^ y >> 27) & 1) | y << 1)
    z = (((z >> 31 ^ z >> 30 ^ z >> 29 ^ z >> 28 ^ z >> 26 ^ z >> 24) & 1) | z << 1)
    if i % 8 == 0:
        num += 1
    KeyStream[num] = ((KeyStream[num] << 1) | (((z >> 32 & 1 & (x >> 30 & 1)) ^ (((z
                                                                       >> 32 & 1) ^ 1) & (
                                                                             y >> 31 & 1))) & 0xffffffff) & 0xff)
first = [101, 5, 80, 213, 163, 26, 59, 38, 19, 6, 173, 189, 198, 166, 140, 183, 42, 247, 223, 24, 106, 20, 145, 37, 24,
         7, 22, 191, 110, 179, 227, 5, 62, 9, 13, 17, 65, 22, 37, 5]
for i in range(len(first)):
     s.add(first[i] == KeyStream[i])
if s.check() == sat:
     ans = s.model()
     print(ans)
~~~

得到x、y、z，再去逆向ParseKey

~~~python
x = 156324965
y = 868387187
z = 3131229747
array = []
array += [x, y, z]
Key = [0] * 12
for i in range(3):
     for j in range(4):
          Key[i*4+j] = (array[i] >> j * 8 & 255)
array5 = [60, 100, 36, 86, 51, 251, 167, 108, 116, 245, 207, 223, 40, 103, 34, 62, 22, 251, 227]
for i in range(len(array5)):
     array5[i] ^= Key[i%12]
print("".join(map(chr, array5)))	# Y0u_@re_G3meM3s7er!
~~~

## goodpy

给的文件里有python的汇编代码，分析逻辑可知

```
tmp[i] = ((ord(flag[i])-9)^51)+8 
取后3个赋给 tmp1 tmp2 tmp3
tmp[31-i]=tmp[31-i-3]  
tmp3=tmp[0] 
tmp2=tmp[1] 
tmp1=tmp[2] 
if i%7!=1 tmp[i]^=119
```

```python
s = [56, 92, 6, 1, 47, 4, 2, 62, 129, 84, 97, 100, 5, 100, 87, 89, 60, 11, 84, 87, 244, 103, 118, 247, 47, 96, 47, 244, 98, 127, 81, 102]
for i in range(len(s)):
    if i % 7 != 1:
        s[i] = (((((s[i] ^ 119) - 8) & 0xff) ^ 51) + 9) & 0xff
    else:
        s[i] = ((((s[i] - 8) & 0xff) ^ 51) + 9) & 0xff
print(s)
s = "".join(map(chr, s))
print(s)
s = s[3:]+s[:3][::-1]
print(s)
```

## simplere

迷宫+base64魔改表，过于简单

## 其他

这周是真忙，第一次项目开会出差，第一次去了武汉。虽然很忙，但是还是抽空在那边吃喝玩乐了一番【武汉菜、小吃、黄鹤楼（真赞，去的时候人还好不是很多，体验挺好还免门票）】，可惜没去成武汉网安基地，本来还想见见朋友，无奈太远了来回都3小时了，泪目。

然后周末回学校把[三叶草新生赛第一周]()的re题目全做了出来，外加一些简单的crypto+misc。不得不说不愧是强队，出的基础题都很有价值，恶补了一些知识，如64位手动脱壳、z3、汇编代码分析、加密算法魔改等（安卓java那道tea类魔改题是真的知识盲区了，才知道java那个int范围不太一样，解密算法最好还是java来写）

哦对，这里补充下第四周快周末那几天做了SCUCTF新生赛，题目出得很拉（re一般，其他方向拉了一堆真题过来）

有2道re题还行，一道smc费点时间，代码很好读；一道出题人直接从网上找的flappy bird python源码转成了exe，里面插入了rand随机数，初始seed已知，但是很难确定rand的顺序（有个randrange和randbyte），逆向pyc后逻辑很乱，最后还是找到源码直接插入rand看顺序才找到每次异或的值和顺序

还有到五子棋那道纯纯算法吧，有点恶心
