## 0x01 Brief About ElfHook

&emsp;&emsp;ElfHook的代码参考boyliang的AllHookInOne

- .dynmaic节中没有DT\_HAST，使用DT\_GNU\_HASH的情况下.


- 计算动态库加载的base\_addr是错误的，应该使用bias\_addr来计算出ehdr、phdr和shdr之外的所有地址。

- 替换函数时，修改page的读写权限时，在SEAndroid上PROT\_EXEC和PROT\_WRITE同时设置**可能**会导致异常，

- 在dlopen返回时，通过返回值获得动态库加载的base\_addr

- elfhook 支持 aarch64 (arm64-v8a)，soinfo的处理暂**不支持**

- android 6以下系统使用/proc/self/maps来检索进程内动态库，android 7以上使用soinfo_list


ref:

&emsp;AllHookInOne : [https://github.com/boyliang/AllHookInOne.git]

&emsp;AllHookInOne说明 : [http://bbs.pediy.com/showthread.php?p=1328038]

&emsp;bionic : [https://android.googlesource.com/platform/bionic]


## 0x02 How To Build

#### Export android ndk path

> export -p PATH=$PATH:$ANDROID_NDK


#### Build

> make

> make clean

> make install  # copy libElfHook.so to jniLibs dir in Demo. 

#### or

> ndk-build NDK\_PROJECT\_PATH=. NDK\_OUT=./objs NDK\_LIBS\_OUT=./bin APP\_BUILD\_SCRIPT=./Android.mk APP\_PLATFORM=android-23 APP\_ABI=arm64-v8a,armeabi-v7a APP_STL=stlport\_static

## 0x03 How To Use


elf\_file用于解析文件形式的elf文件, elf\_module用于解析加载到内存中的elf文件, elf_hooker 封装linker中解析出来的私有方法和对象，例如dlopen\_ext、soinfo\_list等

### 3.1 elf\_hooker接口

- bool elf\_hooker::load()

elf\_hooker初始化，解析出linker中在hook过程中需要使用到的变量和方法的地址。

- void elf\_hooker::dump\_module\_list()

打印在android 6以下版本，使用/proc/self/maps中解析出来当前已经加载的所有动态库的名字和基地址

- void elf\_hooker::dump\_soinfo\_list()

打印在android 7以上版本，soinfo\_list链表中所有soinfo对象的动态库文件路径和内存中的基地址


- void elf\_hooker::set\_prehook\_cb( prehook_cb ):

设置回调函数，用于检查该动态库是否hook

> bool prehook\_cb(const char* module_name);

> 参数:
>> module\_name: 动态库路径

>返回值:
>
>> true: 可以hook
>> 
>> false: 不需要hook

- void elf_hooker::hook\_all\_modules(struct elf\_rebinds * rebinds)

劫持elf\_hooker中解析出来当前已加载所有动态库

````
struct elf_rebinds {
    const char * func_name;
    void * pfn_new;
    void ** ppfn_old;
};
````

> &emsp;func\_name: 要劫持的函数名.

> &emsp;pfn\_new: 新函数地址

> &emsp;ppfn\_old: 返回的劫持前原函数地址, **ppfn\_old非空**

### 3.2 elf\_module接口

- elf\_module::elf\_module(ElfW(Addr) base\_addr, const char* module\_name)

elf\_module构造函数，传入elf内存基地址和文件路径作为参数，如果使用无参数的默认构造函数，则在调用load前需要调用set\_base\_addr()和 set\_module\_name()设置基地址和路径。

- bool elf\_module::load()

解析elf格式

- bool elf\_module:hook(const char \* symbol, void \* replace\_func, void \*\* old\_func);

劫持当前模块中的symbol函数，

> &emsp; symbol: 要劫持的函数名.

> &emsp; replace\_func: 新函数地址

> &emsp; old\_func: 返回的劫持前原函数地址, **old\_func非空**