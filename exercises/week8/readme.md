# Week 8（2024.11.3-2024.11.10）

高强度打完强网实在太累了，甚至网鼎都没去做，只是看了看题，一看就很失望。之后开始写论文了，每周打打极客大挑战的新生赛，毕竟质量高而且我也很菜，晚上就抽些时间来专项练习下，当放松了。

## 反调试

结合着《逆向工程核心原理》知识做个总结和针对性练习

反调试技术对OS依赖性很强，有些反调试技术只能在特定OS下起作用。

可以分为**静态和动态反调试技术**，前者**开始时破解一次**即可解除所有反调试限制，而后者更复杂可能要**一边调试一边破解**

### PEB（进程环境块）

PEB结构体信息里的**BeingDebugged**（1）和**NtGlobalFlag**（0x70），前者是一个标志用来表示进程是否处于被调试的状态，后者是成员变量，与被调试进程的堆内存特性相关

* BeingDebugged：IsDebuggerPresent()可以获取PEB.BeingDebugged（+0x30）的值（原理：先获取TEB结构体地址FS:[18h]，再通过TEB.ProcessEnvironmentBlock成员获取PEB地址，然后访问PEB.BeingDebugged）；另一种检测调试方法是直接FS:[0x30]（64位的话0x60）获取PEB地址；**绕过方法**：nop掉api调用、BeingDebugged设为0
* NtGlobalFlag：获取PEB.NtGlobalFlag（+0x68）的值，0x70则正在调试；**绕过方法**：设为0

### NtQueryInformationProcess()

Ntdll.dll中的一个API，第一个参数是进程句柄，第二个参数是需要提取进程信息的类型，指定该值为特定值可以获取相关信息到第三个参数

~~~c++
__kernel_entry NTSTATUS NtQueryInformationProcess(
  [in]            HANDLE           ProcessHandle,
  [in]            PROCESSINFOCLASS ProcessInformationClass,
  [out]           PVOID            ProcessInformation,
  [in]            ULONG            ProcessInformationLength,
  [out, optional] PULONG           ReturnLength
);
~~~

ProcessInformationClass枚举类型里和反调试相关的成员有：

* ProcessDebugPort（0x7）：若进程正在被调试，则返回0xffffffff，否则返回0；win api CheckRemoteDebuggerPresent()就是调用NtQueryInformationProcess并检查调试端口
* ProcessDebugObjectHandle（0x1e）：若进程处于调试状态，则调试对象句柄的值存在，反之为NULL
* ProcessDebugFlags（0x1f）：若被调试则0，反之1

### NtQuerySystemInformation()

同样是Ntdll.dll中的一个API

~~~c++
__kernel_entry NTSTATUS NtQuerySystemInformation(
  [in]            SYSTEM_INFORMATION_CLASS SystemInformationClass,
  [in, out]       PVOID                    SystemInformation,
  [in]            ULONG                    SystemInformationLength,
  [out, optional] PULONG                   ReturnLength
);
~~~

SystemInformationClass指定需要的系统信息类型，其中和反调试相关的是SystemKernelDebuggerInformation值（0x23），若被调试则SystemInformation为结构体SYSTEM_KERNEL_DEBUGGER_INFORMATION的位置，该结构体的DebuggerEnabled成员值设置为1

### NtQueryObject()

系统中某个调试器调试进程的时候会创建一个调试对象类型的内核对象（“DebugObject”），检测该对象句柄是否存在可以判断是否存在调试

~~~c++
__kernel_entry NTSYSCALLAPI NTSTATUS NtQueryObject(
  [in, optional]  HANDLE                   Handle,
  [in]            OBJECT_INFORMATION_CLASS ObjectInformationClass,
  [out, optional] PVOID                    ObjectInformation,
  [in]            ULONG                    ObjectInformationLength,
  [out, optional] PULONG                   ReturnLength
);
~~~

向第二个参数ObjectInformationClass传入3可以获取ObjectAllTypesInformation（系统所有对象信息）

### ZwSetInformationThread()

利用ZwSetInformationThread() api，被调试者可以将自身从调试器中分离出来

~~~c++
NTSYSAPI NTSTATUS ZwSetInformationThread(
  [in] HANDLE          ThreadHandle,
  [in] THREADINFOCLASS ThreadInformationClass,
  [in] PVOID           ThreadInformation,
  [in] ULONG           ThreadInformationLength
);
~~~

第一个参数ThreadHandle用来接收当前线程的句柄，第二个参数ThreadInformationClass表示线程信息类型，若其值设置为ThreadHideFromDebugger（0x11），则调用该函数会使得调试器程序终止，同时终止自身进程，而正常程序不受影响

### TLS回调函数

通常会在TLS里进行反调试

### SetLastError & OutputDebugStringA & GetLastError

直接贴了看雪的讲解，这个反调试技术目前还没看到过

编写应用程序时，经常需要涉及到错误处理问题。许多函数调用只用TRUE和FALSE来表明函数的运行结果。一旦出现错误，MSDN中往往会指出请用GetLastError()函数来获得错误原因。恶意代码可以使用异常来破坏或者探测调试器。调试器捕获异常后，并不会立即将处理权返回被调试进程处理，大多数利用异常的反调试技术往往据此来检测调试器。多数调试器默认的设置是捕获异常后不将异常传递给应用程序。如果调试器不能将异常结果正确返回到被调试进程，那么这种异常失效可以被进程内部的异常处理机制探测。
对于OutputDebugString函数，它的作用是在调试器中显示一个字符串，同时它也可以用来探测调试器的存在。使用SetLastError函数，将当前的错误码设置为一个任意值。如果进程没有被调试器附加，调用OutputDebugString函数会失败，错误码会重新设置，因此GetLastError获取的错误码应该不是我们设置的任意值。但如果进程被调试器附加，调用OutputDebugString函数会成功，这时GetLastError获取的错误码应该没改变。

~~~c++
BOOL CheckDebug()  
{  
    DWORD errorValue = 12345;  
    SetLastError(errorValue);  
    OutputDebugString("Test for debugger!");  
    if (GetLastError() == errorValue)  
    {  
        return TRUE;  
    }  
    else  
    {  
        return FALSE;  
    }  
}
~~~

-----

前面都是静态反调试技术，后面是动态反调试技术

### 异常

正常运行的进程发生异常时，在SEH机制的作用下，OS会接收异常，然后调用进程中注册的SEH处理；但是若进程在调试运行中发生异常，调试器会接收处理。因此可以利用这种特征来判断调试

#### SEH

Windows中最具代表性的异常是断电异常：BreakPoint指令触发异常时，若程序处于调试运行状态，则系统会立即停止运行并将控制权交给调试器。通常反调试可以设置只有在SEH处理中修改EIP值，使得运行代码位置发生变化，即使没有EIP的变化也可能有静态反调试技术                 

跟着书里一个案例走一下流程：

1. 安装SEH

   ~~~assembly
   PUSH 40102C				; SEH
   PUSH DWORD PTR FS:[0]
   MOV DWORD PTR FS:[0],ESP
   ~~~

2. 发生INT3异常

   ~~~assembly
   INT3
   ~~~

3. 调试的话会继续运行接下来的命令

   ~~~assembly
   MOV EAX,-1
   JMP EAX					; 跳转非法地址
   ~~~

   非调试的话-运行SEH

   ~~~assembly
   MOV EAX,DWORD PTR SS:[ESP+C]		; CONTEXT *pContext结构体的指针，正是SEH的第三个参数
   MOV EBX,401040
   MOV DWORD PTR DS:[EAX+B8],EBX		; DS:[EAX+B8]指向pContext->Eip成员，相当于修改了eip为401040
   XOR EAX,EAX
   RETN
   ~~~

4. 删除SEH

   ~~~assembly
   POP DWORD PTR FS:[0]
   ADD ESP,4

SEH函数定义如下：

~~~c++
EXCEPTION_DISPOSITION ExceptHandler
{
    EXCEPTION_RECORD *pRecord,
    EXCEPTION_REGISTRATION_RECORD *pFrmae,
    CONTEXT *pContext,
    PVOID pValue
};
typedf enum_EXCEPTION_DISPOSITION {
    ExceptionContinueExecution,
    ExceptionContinueSearch,
    ExpcetionNestedException,
    ExceptionCollidedUnwind
} EXCEPTION_DISPOSITION;
~~~

CONTEXT结构体定义如下

~~~c
typedef struct _CONTEXT
{
    DWORD ContextFlags;
    DWORD Dr0;
    DWORD Dr1;
    DWORD Dr2;
    DWORD Dr3;
    DWORD Dr6;
    DWORD Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD SegGs;
    DWORD SegFs;
    DWORD SegEs;
    DWORD SegDs;
    DWORD Edi;
    DWORD Esi;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
    DWORD Ebp;
    DWORD Eip;
    DWORD SegCs;
    DWORD EFlags;
    DWORD Esp;
    DWORD SegSs;
} CONTEXT;
~~~

必须处理异常否则会无限循环（又去执行INT3）导致栈溢出

破解方法：调试器设置忽略被调试进程中发生的INT3异常，而由自身SEH处理

#### SetUnhandledExceptionFilter()

若进程发生异常时没有SEH处理，则会调用执行系统的kernel32 api SetUnhandledExceptionFilter()，该函数内部运行系统的最后一个异常处理器（Top Level Exception Filter或Last Exception Filter），弹出错误消息框，然后终止进程运行

有意思的是SetUnhandledExceptionFilter里调用了NtQueryInformationProcess api，来判断是否在调试程序。若非调试，则运行系统最后的异常处理器（Top Level Exception Filter）；反之将异常派送给调试器

因此基于异常的反调试技术中，通常特意触发异常，然后在新注册的Last Exception Filter内部判断是否调试，根据结果修改EIP值

破解方法：API钩取

### Timing Check

调试运行程序代码时间比正常的多得多，可以根据运行时间差异判断是否调试

#### 时间间隔测量法

* Counter based method：RDTSC、kernel32!QueryPerformanceCounter()/ntdll!NtQueryPerformanceCounter()、kernel32!GetTickCount()
* Time based method：timeGetTime()、\_ftime()

其中计数器准确程度：RDTSC>NtQueryPerformanceCounter>GetTickCount，精度最高的是其是CPU内部的计数器

破解方法：直接run过去、修改计数器值、操作条件分支指令

### 陷阱标志

陷阱标志（Trap Flag，TF）指EFLAGS寄存器的第九个比特位

#### 单步执行

TF值设置为1时，CPU将进入单步执行模式。在该模式中，CPU执行1条指令后就会触发1个EXCEPTION_SINGLE_STEP异常，然后TF自动清0

破解方法：修改调试选项忽略EXCEPTION_SINGLE_STEP异常

#### INT 2D

原为内核模式中用来触发断点异常的指令，也可以在用户模式下触发异常。但程序调试运行时不会触发异常，只是忽略。

调试模式下执行完INT 2D会忽略下一条指令的第一个字节，从而达到混淆代码的作用

另一种特征是使用StepInto或StepOver命令跟踪INT 2D时程序会一直运行直到遇到断点，类似F9

### 0xCC探测

程序调试时会设置软件断点，对应的x86指令为0xCC

#### API断点

检测API代码第一个字节是否为CC即可判断是否处于调试

破解方法：api断点尽量避开第一个字节，可以设置在代码的中间部分

#### 比较校验和

比较特定代码区域的校验和值