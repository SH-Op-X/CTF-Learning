# Week 14（2024.12.16-2024.12.22）

## libdroid

之前菜没搞懂安卓调用，重新做下

~~~java
public class a extends AppCompatActivity {
    static String a;
    static String b;
    static String c;
    static String d;
    String e;
    static Object f;
    static String flag;
    static String g;

    static {
        System.loadLibrary("libdroid");
        a.a = a.a(a.getOperatingSystem(), 1);
        a.b = a.a(a.getPhoneNumber(), 1);
        a.c = a.a(a.installRootkit(), 1);
        a.d = a.a(a.generateConfusion(), 1);
        a.f = a.a(a.obtainWorldDomination(), 1);
        a.g = a.a(a.installiOS(), 1);
        a.flag = a.a(a.getFlag(), 1);
    }

    static String a(String arg8, int arg9) {
        StackTraceElement a0 = new Exception().getStackTrace()[arg9];
        StringBuilder a1 = new StringBuilder();
        a1.append(a0.getClassName()).insert(arg9, a0.getMethodName());
        String a1 = a1.toString();
        char[] a2 = new char[arg8.length()];
        char a4 = '\u0000';
        char a3 = (char)a1.length();
        while(a4 < arg8.length()) {
            a2[a4] = (char)(a1.charAt(a3 - 1) ^ (arg8.charAt(((int)a4)) ^ 18));
            char v4_1 = (char)(a4 + 1);
            if(v4_1 >= arg8.length()) {
                break;
            }

            a2[v4_1] = (char)(a1.charAt(a3 - 1) ^ (arg8.charAt(((int)v4_1)) ^ 0xFA));
            a4 = (char)(v4_1 + 1);
            a3 = (char)(a3 - 1);
            if(a3 > 0) {
                continue;
            }

            a3 = (char)a1.length();
        }

        return String.valueOf(a2);
    }
    //...
}
~~~

为了搞懂Exception().getStackTrace()的调用结果，专门写了个java脚本测试

~~~java
public class a {
    static String a;
    static {
        a = b("", 1);
    }
    static String b(String arg8, int arg9) {
        StackTraceElement a0 = new Exception().getStackTrace()[arg9];
        StringBuilder a1 = new StringBuilder();
        a1.append(a0.getClassName()).insert(1, a0.getMethodName());
        System.out.println(a1.toString());
        return "";
    }
    public static void main(String[] args) {
        System.out.println("aaaa");
    }
}

~~~

结果为`a<clinit>`，安卓的getClassName会打印全称，因此实际结果为`c<clinit>tf.stratumauhhur.libdroid.a`，解密即可

~~~python
s = [1, 244, 83, 160, 29, 247, 15, 174]
key = b"c<clinit>tf.stratumauhhur.libdroid.a"
k = len(key)
for i in range(0, len(s), 2):
    s[i] ^= 18 ^ key[k-1]
    s[i+1] ^= 0xfa ^ key[k-1]
    k -= 1
    if k == 0:
        k = len(key)
print("".join(map(chr, s)))
~~~

直接去so文件里取数据即可，最终abcdfg和flag结果如下

~~~java
config.ini
blablablabla
Congratula
 1234567890
key=
rootkit=
Sorry no rootkit for you :(
~~~

然后从头分析oncreate，发现读取了config.ini内容和a.b循环异或

~~~java
void a(String arg11) throws Exception {
    InputStream b = this.getAssets().open(arg11);
    ByteArrayOutputStream b2 = new ByteArrayOutputStream();
    byte[] data = new byte[0x4000];
    while(true) {
        int nRead = b.read(data, 0, data.length);
        if(nRead == -1) {
            break;
        }

        b2.write(data, 0, nRead);
    }

    b2.flush();
    BufferedReader b4 = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(this.a(b2.toByteArray(), a.b))));
    while(true) {
    label_23:
        String c = b4.readLine();
        if(c == null) {
            return;
        }

        if(c.startsWith(a.g)) {	// rootkit=
            a.g = c.substring(a.g.length());
        }

        if(!c.startsWith(((String)a.f))) {	// key=
            goto label_23;
        }

        a.f = Base64.decode(c.substring(((String)a.f).length()), 0);	// base64解密结果赋给a.f
    }
}

byte[] a(byte[] arg5, String arg6) {
    byte[] a2 = new byte[arg5.length];
    char a3;
    for(a3 = '\u0000'; a3 < a2.length; a3 = (char)(a3 + 1)) {
        a2[a3] = (byte)(arg5[a3] ^ arg6.charAt(a3 % arg6.length()));
    }

    return a2;
}
@Override  // android.support.v7.app.AppCompatActivity
protected void onCreate(Bundle arg2) {
    super.onCreate(arg2);
    this.setContentView(0x7F040019);  // layout:activity_a
    try {
        this.a(a.a);
    }
    catch(Exception v0) {
    }

    this.e = "";
}
~~~

再次解密得到

~~~python
key = b"blablablabla"
with open("config.ini", "rb") as f:
    data = list(f.read())
for i in range(len(data)):
    data[i] ^= key[i%len(key)]
print("".join(map(chr,data)))
"""
<root>
key=IQCGt/+GXQYtMA==
rootkit=a/d/c/c
</root>
"""
~~~

发现base64解密之后貌似结束了，实际上还有一个a函数分析下可知是点击按钮6次进行检查，每个按钮对应1234567890

~~~java
public void a(View arg15) {
    String flag;
    if(arg15.getId() == 0x7F0C0069) {  // id:button
        this.e = this.e + ((char)a.d.charAt(1));
    }

    if(arg15.getId() == 0x7F0C006A) {  // id:button2
        this.e = this.e + ((char)a.d.charAt(2));
    }

    if(arg15.getId() == 0x7F0C006B) {  // id:button3
        this.e = this.e + ((char)a.d.charAt(3));
    }

    if(arg15.getId() == 0x7F0C006C) {  // id:button4
        this.e = this.e + ((char)a.d.charAt(4));
    }

    if(arg15.getId() == 0x7F0C006D) {  // id:button5
        this.e = this.e + ((char)a.d.charAt(5));
    }

    if(arg15.getId() == 0x7F0C006E) {  // id:button6
        this.e = this.e + ((char)a.d.charAt(6));
    }

    if(arg15.getId() == 0x7F0C006F) {  // id:button7
        this.e = this.e + ((char)a.d.charAt(7));
    }

    if(arg15.getId() == 0x7F0C0071) {  // id:button8
        this.e = this.e + ((char)a.d.charAt(8));
    }

    if(arg15.getId() == 0x7F0C0072) {  // id:button9
        this.e = this.e + ((char)a.d.charAt(9));
    }

    if(arg15.getId() == 0x7F0C0070) {  // id:button10
        this.e = this.e + ((char)a.d.charAt(0));
    }

    if(this.e.length() == 6 || arg15.getId() == 0x7F0C0073) {  // id:button11
        String flag = a.flag;
        try {
            InputStream b = this.getAssets().open(a.g);
            ByteArrayOutputStream b2 = new ByteArrayOutputStream();
            byte[] data = new byte[0x4000];
            while(true) {
                int nRead = b.read(data, 0, data.length);
                if(nRead == -1) {
                    break;
                }

                b2.write(data, 0, nRead);
            }

            b2.flush();
            byte[] j = b2.toByteArray();
            byte[] f_ = new byte[16];
            System.arraycopy(((byte[])a.f), 0, f_, 0, ((byte[])a.f).length);
            System.arraycopy(this.e.getBytes(), 0, f_, 10, this.e.getBytes().length);	// 传入的正好是key=6个数字
            a.phoneHome(j, f_);
            if(new String(j).startsWith(a.c)) {
                flag = new String(j);
                goto label_186;
            }
        }
        catch(Exception e1) {
            e1.printStackTrace();
        }

        goto label_188;
    label_186:
        flag = flag;
    label_188:
        Snackbar.make(arg15, flag, 0).setAction("Action", null).show();
        this.e = "";
    }
}
~~~

查看so里的phoneHome很明显tea加密，需要爆破key值，key值正好是base64解密的10字节+6字节输入

~~~c
__int64 __fastcall Java_ctf_stratumauhhur_libdroid_a_phoneHome(JNIEnv *a1, __int64 a2, __int64 a3, __int64 a4)
{//...
  v7 = ((__int64 (__fastcall *)(JNIEnv *, __int64, _QWORD))(*a1)->GetByteArrayElements)(a1, a3, 0LL);
  key = (unsigned __int8 *)((__int64 (__fastcall *)(JNIEnv *, __int64, _QWORD))(*a1)->GetByteArrayElements)(a1, a4, 0LL);
  v9 = ((__int64 (__fastcall *)(JNIEnv *, __int64))(*a1)->GetArrayLength)(a1, a3);
  v10 = *key | ((char)key[3] << 24) | (unsigned __int16)((char)key[1] << 8) | (key[2] << 16);
  v11 = (unsigned __int16)((char)key[5] << 8) | key[4] | ((char)key[7] << 24) | (key[6] << 16);
  v12 = key[8] | ((char)key[11] << 24) | (unsigned __int16)((char)key[9] << 8) | (key[10] << 16);
  v13 = key[12] | ((char)key[15] << 24) | (unsigned __int16)((char)key[13] << 8) | (key[14] << 16);
  if ( v9 > 0 )
  {
    v14 = (char *)(v7 + 1);
    v15 = v7 + 8LL * ((unsigned int)(v9 - 1) >> 3) + 9;
    do
    {
      v16 = -709370400;
      v17 = (unsigned __int16)(*v14 << 8) | (unsigned __int8)*(v14 - 1) | (v14[2] << 24) | ((unsigned __int8)v14[1] << 16);
      v18 = (unsigned __int16)(v14[4] << 8) | (unsigned __int8)v14[3] | (v14[6] << 24) | ((unsigned __int8)v14[5] << 16);
      do
      {
        v18 -= (v17 + v16) ^ (16 * v17 + v12) ^ (v13 + (v17 >> 5));
        v17 -= (v18 + v16) ^ (16 * v18 + v10) ^ (v11 + (v18 >> 5));
        v16 += 559038737;
      }
      while ( v16 );
      v14 += 8;
      *(v14 - 8) = BYTE1(v17);
      *(v14 - 7) = BYTE2(v17);
      *(v14 - 4) = BYTE1(v18);
      *(v14 - 9) = v17;
      *(v14 - 5) = v18;
      *(v14 - 3) = BYTE2(v18);
      *(v14 - 6) = HIBYTE(v17);
      *(v14 - 2) = HIBYTE(v18);
    }
    while ( v14 != (char *)v15 );
  }
  ((void (__fastcall *)(JNIEnv *, __int64, __int64, _QWORD))(*a1)->ReleaseByteArrayElements)(a1, a3, v7, 0LL);
  return ((__int64 (__fastcall *)(JNIEnv *, __int64, unsigned __int8 *, _QWORD))(*a1)->ReleaseByteArrayElements)(
           a1,
           a4,
           key,
           0LL);
}
~~~

启动爆破，密文是a/d/c/c

~~~python
from base64 import b64decode
import struct
from ctypes import c_uint32
from itertools import product


def tea_decrypt(v, key, delta):
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    total = c_uint32(0xD5B7DDE0)
    while True:
        v1.value -= ((v0.value << 4) + key[2]) ^ (v0.value + total.value) ^ ((v0.value >> 5) + key[3])
        v0.value -= ((v1.value << 4) + key[0]) ^ (v1.value + total.value) ^ ((v1.value >> 5) + key[1])
        total.value += delta
        if total.value == 0:
            break
    return v0.value, v1.value


with open("c", "rb") as f:
    data = list(f.read())
for i in product([32]+list(range(49, 58)), repeat=6):
    v = [struct.unpack("<I", bytes(data[i:i+4]))[0] for i in range(0, len(data), 4)]
    key = list(b64decode(b"IQCGt/+GXQYtMA==")) + list(i)
    key = [struct.unpack("<I", bytes(key[i:i+4]))[0] for i in range(0, len(key), 4)]
    delta = 0x21524111
    for i in range(0, len(v), 2):
        v[i:i+2] = tea_decrypt(v[i:i+2], key, delta)
    str_list = []
    try:
        for i in range(len(v)):
            str_list.append(struct.pack('<I', v[i]).decode())
        print('decrypted: %s' % ''.join(str_list))
        break
    except:
        continue
# decrypted: Congratulations! The rootkit is sucessfully installed. The Flag is 32C3_this_is_build_for_flag_ship_phones      
~~~

## whats-the-hell-500

挺有意思，导入的stl（sxx）文件重载了很多类和运算符，但可以完全无视直接cout值，然后z3求解

~~~python
from z3 import *

s = Solver()
p = [Int(f"p{i}") for i in range(13)]
cmp = [101, 143, 5035, 163, 226, 5814, 205, 173, 9744, 5375, 4670, 205]
s.add(p[0]+p[1]==101)
s.add(p[1]+p[2]==143)
s.add(p[0]*p[2]==5035)
s.add(p[3]+p[5]==163)
s.add(p[3]+p[4]==226)
s.add(p[4]*p[5]==5814)
s.add(p[7]+p[8]==205)
s.add(p[6]+p[8]==173)
s.add(p[6]*p[7]==9744)
s.add(p[9]+p[10]*p[11]==5375)
s.add(p[10]+p[9]*p[11]==4670)
s.add(p[9]+p[10]==205)
s.add(p[12]==ord("w"))
for i in range(13):
    s.add(p[i] < 128)
if s.check() == sat:
    ans = s.model()
    for i in p:
        print(chr(ans[i].as_long()), end="")
~~~

