# TetCTF-Reverse

## MagicBox

vm题目，可以动态调试提取lpAddress后的数据

~~~c
int sub_4010AD()
{
  _WORD *v0; // eax
  _WORD *v1; // esi

  v0 = VirtualAlloc(0, 0x20000u, 0x1000u, 4u);
  v1 = v0;
  lpAddress = v0;
  if ( v0 )
  {
    memcpy(v0 + 300, &unk_404018, 0x3246u);
    *v1 = 300;
    if ( !(unsigned __int8)sub_401000() )
      printf("Failed to run program\n");
    if ( lpAddress )
    {
      VirtualFree(lpAddress, 0, 0x8000u);
      lpAddress = 0;
    }
  }
  else
  {
    printf("Failed to init program\n");
  }
  return 0;
}

int sub_401000()
{
  unsigned __int16 *v0; // ebx
  int result; // eax
  int v2; // edx
  int v3; // ecx
  int v4; // esi
  int v5; // edi

  v0 = (unsigned __int16 *)lpAddress;
  for ( result = 1; *v0 != 0xFFFF; result = 1 )
  {
    if ( v0[4] == 1 )
    {
      v0[4] = 0;
      printf("%c", v0[3]);
      v0 = (unsigned __int16 *)lpAddress;
    }
    if ( v0[6] == 1 )
    {
      v0[6] = 0;
      scanf("%c", v0 + 5);
      v0 = (unsigned __int16 *)lpAddress;
    }
    v2 = *v0;
    v3 = v0[v2 + 1];
    v4 = v0[v2];
    v5 = v0[v2 + 2];
    *v0 = v2 + 3;
    LOWORD(v3) = ~(v0[v4] | v0[v3]);
    v0[v5] = v3;
    v0[1] = __ROL2__(v3, 1);
  }
  return result;
}
~~~

可以利用python模拟vm流程

~~~python
import string

data = [...]
data[0] = 300
i = 0
k = 0
s = string.ascii_uppercase
while data[i] != 0xffff:
    if data[4] == 1:
        data[4] = 0
        print("printf char ", chr(data[3]))
        i = 0
    if data[6] == 1:
        data[6] = 0
        print(f"scanf {s[k]} to data[5]")
        data[5] = ord(s[k])
        k += 1
        i = 0
    v2 = data[0]
    v3 = data[v2 + 1]
    v4 = data[v2]
    v5 = data[v2 + 2]
    data[0] = v2 + 3
    tmp = v3
    v3 = 0xffff-(data[v4] | data[v3])
    data[v5] = v3   # v3用来修改内容
    print(f"data[{v5}]=~(data[{v4}]|data[{tmp}])" if v4 != tmp else f"data[{v5}]=~data[{v4}]")
    data[1] = ((v3 << 1) | (v3 >> 15)) & 0xffff
    # data[494] = 0
print(k)
"""
data[7]=~data[6720]
data[3]=~data[7]
data[7]=~data[312]
data[0]=~data[7]
data[7]=~data[313]
data[4]=~data[7]
printf char  P
data[7]=~data[6719]
data[3]=~data[7]
data[7]=~data[332]
data[0]=~data[7]
data[7]=~data[333]
data[4]=~data[7]
printf char  a
...
printf char  g
data[7]=~data[5967]
data[0]=~data[7]
data[7]=~data[5968]
data[0]=~data[7]
26
"""
~~~

可以看到打印了`password:`和`wrong`，统计scanf发现输入26次

通过分析各种非运算和或运算，发现每次检查的结果都会存到data[494]

~~~
data[1022]=~data[6691]
data[1023]=~data[6670]
data[7]=~data[1036]
data[0]=~data[7]
data[1037]=~data[6691]
data[1038]=~data[1023]
data[7]=~(data[1037]|data[1038])
data[7]=~data[7]
data[1023]=~data[7]
data[7]=~data[1060]
data[0]=~data[7]
data[1061]=~data[6670]
data[1062]=~data[1022]
data[7]=~(data[1061]|data[1062])
data[7]=~data[7]
data[1022]=~data[7]
data[7]=~(data[1022]|data[1023])
data[6669]=~data[7]
data[7]=~(data[6669]|data[494])
data[494]=~data[7]
~~~

在每个循环后设置`data[494]=0`，发现打印的结果发生变化，打印`TetCTF{输入的26字符}`

因此只需保证每次`data[494]==0`，写个爆破脚本

~~~python
def brute_force():
    s = list(string.ascii_uppercase)
    for x in range(26):
        j = 48
        while j < 128:
            data = [...]
            k = 0
            s[x] = chr(j)
            if j == 58 or j == 60:
                j += 1
                continue
            right_char = 0
            while data[0] != 0xffff:
                if data[4] == 1:
                    data[4] = 0
                if data[6] == 1:
                    data[6] = 0
                    data[5] = ord(s[k])
                    k += 1
                v2 = data[0]
                v3 = data[v2 + 1]
                v4 = data[v2]
                v5 = data[v2 + 2]
                data[0] = v2 + 3
                tmp = v3
                v3 = 0xffff - (data[v4] | data[v3])
                data[v5] = v3  # v3用来修改内容
                data[1] = ((v3 << 1) | (v3 >> 15)) & 0xffff
                if v5 == 494:
                    if v3 != 0:   # 不是该字符
                        break
                    else:
                        right_char += 1
            if right_char == x + 1:
                if x == 15: # 这里过不去，不知道啥情况，感觉是多解了，只能手动指定
                    s[15] = "@"
                break
            j += 1
        print(s[x], end="")

brute_force()	# WE1rd_v1R7UaL_M@chINE_Ev3R
~~~

有一点要注意中间有个字符爆破不过去，得手动设置

## Hidden

> The way that I decode the media file.

> 目前只找到一个解：https://hackmd.io/@mochinishimiya/SJ4JpI1ht#RE-hidden，但是看到一半看不懂怎么个dll劫持，留待以后学习

主函数全是windows api，很多关于媒体读写操作的，正常跑完会获得一个`嘲讽.jpeg`

<img src=".\Reverse\hidden\flag.jpeg" alt="flag" style="zoom:25%;" />

分析下主函数代码，截取部分分析

~~~c
if ( argc != 8 )	// 这里会检查输入参数个数从而确定执行流
{
    if ( !RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"Software\\Classes\\CLSID\\{26613686-ae12-4b5c-9139-4c8211b45a4b}\\Parameters",
            0,
            0x20019u,
            (PHKEY)&TokenHandle) )              // 读取和写入注册表
    {
    	cbData = 16;
		v8 = RegQueryValueExW((HKEY)TokenHandle, L"1", 0, 0, Data, &cbData);
		cbData = 4;
		v9 = RegQueryValueExW((HKEY)TokenHandle, L"2", 0, 0, v57, &cbData) | v8;
         cbData = 4;
         v10 = RegQueryValueExW((HKEY)TokenHandle, L"3", 0, 0, v58, &cbData) | v9;
         cbData = 4;
         v11 = RegQueryValueExW((HKEY)TokenHandle, L"4", 0, 0, &v60[4], &cbData) | v10;
         cbData = 4;
         v12 = RegQueryValueExW((HKEY)TokenHandle, L"5", 0, 0, v60, &cbData) | v11;
         cbData = 128;
         v13 = RegQueryValueExW((HKEY)TokenHandle, L"6", 0, 0, (LPBYTE)v71, &cbData) | v12;	// 这里的值比较有意思，为Findme
          RegCloseKey((HKEY)TokenHandle);
          if ( v13 )
          {
            printf("Decode error!\n");
            return 1;
          }
	 }
    goto LABEL_38;	// 会直接跳转不再执行下面的代码
  }	// 输入参数数目够的话执行
  ElementCount = (size_t)argv[2];	
  LibraryW = LoadLibraryW(L"shell32.dll");
  v15 = LibraryW;
  if ( LibraryW )
  {
    ProcAddress = GetProcAddress(LibraryW, (LPCSTR)0x2C0);
    if ( ProcAddress )
    {
LABEL_33:
      ((void (__stdcall *)(size_t, BYTE *))ProcAddress)(ElementCount, Data);
      goto LABEL_34;
    }
    FreeLibrary(v15);
  }
  v17 = LoadLibraryW(L"Shlwapi.dll");
  v15 = v17;
  if ( !v17 )
    goto LABEL_35;
  ProcAddress = GetProcAddress(v17, (LPCSTR)0x10E);
  if ( ProcAddress )
    goto LABEL_33;
LABEL_34:
  FreeLibrary(v15);
LABEL_35:
  *(_DWORD *)v57 = ((int (__usercall *)@<eax>(int@<ecx>, int))unknown_libname_3)(v18, (int)argv[3]);
  *(_DWORD *)v58 = ((int (__usercall *)@<eax>(int@<ecx>, int))unknown_libname_3)(v19, (int)argv[4]);
  *(_DWORD *)v60 = ((int (__usercall *)@<eax>(int@<ecx>, int))unknown_libname_3)(v20, (int)argv[5]);
  v22 = ((int (__usercall *)@<eax>(int@<ecx>, int))unknown_libname_3)(v21, (int)argv[6]);
  v23 = argv[7];
  *(_DWORD *)&v60[4] = v22;
  v24 = (char *)((char *)v71 - v23);
  do
  {
    v25 = *(_WORD *)v23;
    v23 += 2;
    *(_WORD *)&v23[(_DWORD)v24 - 2] = v25;
  }
  while ( v25 );
  malloc(0x20u);
LABEL_38:
  MFCreateMediaType(&ppMFType);
  if ( (*(int (__stdcall **)(int, IMFMediaType *))(*(_DWORD *)v47 + 128))(v47, ppMFType) )
    goto LABEL_111;
  if ( ppMFType->lpVtbl->GetUINT32(ppMFType, (const GUID *const)&unk_4F6220, (UINT32 *)v69) )
  {
    printf((const char *)&unk_4FC043);
    goto LABEL_112;
  }
  if ( (*(int (__stdcall **)(int *, _DWORD, IMFMediaType *, _DWORD))(*v41 + 60))(v41, 0, ppMFType, 0) )
    goto LABEL_111;
  MFCreateMediaType(&v42);
  if ( (*(int (__stdcall **)(int, IMFMediaType *))(*(_DWORD *)v47 + 128))(v47, v42) )
    goto LABEL_111;
  if ( v42->lpVtbl->SetGUID(v42, (const GUID *const)&unk_4F6200, (const GUID *const)"vids") )
    goto LABEL_111;
  if ( v42->lpVtbl->SetGUID(v42, (const GUID *const)&unk_4F6210, (const GUID *const)Data) )
    goto LABEL_111;
  if ( v42->lpVtbl->SetUINT32(v42, (const GUID *const)&unk_4F6220, 3 * *(_DWORD *)v57 * *(_DWORD *)v58) )
    goto LABEL_111;
  if ( ((int (__stdcall *)(IMFMediaType *, void *, _DWORD, _DWORD))v42->lpVtbl->SetUINT64)(
         v42,
         &unk_4F6230,
         *(_DWORD *)v58,
         *(_DWORD *)v57) )
  {
    goto LABEL_111;
  }
  if ( ((int (__stdcall *)(IMFMediaType *, void *, _DWORD, _DWORD))v42->lpVtbl->SetUINT64)(
         v42,
         &unk_4F6240,
         *(_DWORD *)&v60[4],
         *(_DWORD *)v60) )
  {
    goto LABEL_111;
  }
  if ( (*(int (__stdcall **)(int *, _DWORD, IMFMediaType *, _DWORD))(*v41 + 64))(v41, 0, v42, 0) )
    goto LABEL_111;
  if ( (*(int (__stdcall **)(int *, _DWORD, _DWORD))(*v41 + 92))(v41, 0, 0) )
    goto LABEL_111;
  if ( (*(int (__stdcall **)(int *, int, _DWORD))(*v41 + 92))(v41, 0x10000000, 0) )
    goto LABEL_111;
  if ( (*(int (__stdcall **)(int *, int, _DWORD))(*v41 + 92))(v41, 0x10000003, 0) )
    goto LABEL_111;
  printf("Processing sample\n");
  Sleep(0x3E8u);
~~~

## crackme pls

> Just a simple crackme, but we spiced it up a little bit.

> 魔改控制流平坦化，mad，too hard，溜了
