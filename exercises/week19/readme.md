# Week 19（2025.1.20-2025.1.26）

这一周被迫疯狂改论文，忙里抽了点小空打了两场比较垃圾的比赛（打前我也不知道他垃圾哇）

* KnightCTF2025：SU年终之战，花了一整天和队友们AK了所有题目（都很简单，就是太抽象），但只排了第六，ak手速慢了
* 启航杯第一届：看奖品不错组个小队过去冲冲，打完只想说当我没打过吧，re三道题目难度太低了，全是xor（服务器不停的崩、最后osint py狂掉排名），wp我都不准备写了

## [羊城杯 2024]你这主函数保真么

https://www.nssctf.cn/problem/5791

很明显隐藏了逻辑

~~~c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __main();
  puts("I am main!");
  system("cls");
  return 0;
}
~~~

根据符号表命名找到关键加密：一个rot13一个DCT加密

~~~c
int __cdecl rot13_encrypt(char *a1)
{
  int result; // eax
  char v2; // al

  while ( 1 )
  {
    result = (unsigned __int8)*a1;
    if ( !(_BYTE)result )
      break;
    if ( *a1 > 64 && *a1 <= 90 || *a1 > 96 && *a1 <= 122 )
    {
      if ( *a1 <= 64 || *a1 > 90 )
        v2 = 97;
      else
        v2 = 65;
      *a1 = (*a1 - v2 + 13) % 26 + v2;
    }
    ++a1;
  }
  return result;
}
_DWORD *__cdecl encrypt(_DWORD *a1, _DWORD *a2)
{
  double v2; // st7
  double *v3; // eax
  double v4; // st7
  double *v5; // eax
  char v7; // [esp+2Fh] [ebp-39h] BYREF
  double v8; // [esp+30h] [ebp-38h] BYREF
  double v9; // [esp+38h] [ebp-30h]
  double v10; // [esp+40h] [ebp-28h]
  double v11; // [esp+48h] [ebp-20h]
  int v12; // [esp+54h] [ebp-14h]
  int j; // [esp+58h] [ebp-10h]
  int i; // [esp+5Ch] [ebp-Ch]

  v12 = std::vector<int>::size(a2);
  std::allocator<double>::allocator(&v7);
  v8 = 0.0;
  std::vector<double>::vector(v12, &v8, &v7);
  std::allocator<double>::~allocator(&v7);
  for ( i = 0; i < v12; ++i )
  {
    for ( j = 0; j < v12; ++j )
    {
      v11 = (double)*(int *)std::vector<int>::operator[](a2, j);
      v2 = cos(((double)j + 0.5) * ((double)i * 3.141592653589793) / (double)v12);
      v10 = v2 * v11;
      v3 = (double *)std::vector<double>::operator[](a1, i);
      *v3 = *v3 + v10;
    }
    if ( i )
      v4 = sqrt(2.0 / (double)v12);
    else
      v4 = sqrt(1.0 / (double)v12);
    v9 = v4;
    v5 = (double *)std::vector<double>::operator[](a1, i);
    *v5 = *v5 * v9;
  }
  return a1;
}
void __cdecl Test::~Test()
{
  int i; // [esp+2Ch] [ebp-Ch]

  for ( i = 0; i <= 32; ++i )
  {
    if ( std::abs(check[i] - in[i]) > 0.0001 )
    {
      puts("Wrong!!");
      exit(0);
    }
  }
  puts("Right!!");
}
~~~

double数据为check，可以去里面按下alt+d一个个转为double类型，然后提取出来

~~~python
import numpy as np
from scipy.fftpack import idct

s = [513.355, -37.7986, 8.7316, -10.7832, -1.3097, -20.5779, 6.98641, -29.2989, 15.9422, 21.4138, 29.4754, -2.77161, -6.58794, -4.22332, -7.20771, 8.83506, -4.38138, -19.3898, 18.3453, 6.88259, -14.7652, 14.6102, 24.7414, -11.6222, -9.754759999999999, 12.2424, 13.4343, -34.9307, -35.735, -20.0848, 39.689, 21.879, 26.8296]

def idct_numpy(a1):
    """
    使用 NumPy 内置的 IDCT 函数恢复 a2
    :param a1: DCT 变换后的数组
    :return: 恢复的原始数组 a2
    """
    a2 = idct(a1, norm='ortho')  # 使用正交归一化
    a2 = np.round(a2).astype(int)  # 四舍五入并转换为整数
    return a2

s1 = idct_numpy(s)
print("".join(map(chr, s1)))	# 再去做个移位
~~~

