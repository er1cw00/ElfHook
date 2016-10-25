## 0x01 Brief About ElfHook

&emsp;&emsp;ElFKooH is the same as ElfHooK, came from boyliang's AllHookInOne, fix some bug, dealing with new problem in aarch64.

- **NOT** DT_HAST in .dynmaic section，but .gun.hash instead.

- **NOT** DT_REL and DT_RELSZ in .dynmaic section, but DT_ANDROID_REL and DT_ANDROID_RELSZ instead.

- use base_addr to caculate symbol table's offset is wrong，replace it with bias_addr。

- when modify memory page’s read-write permission，set PROT_EXEC and PROT_WRITE together in SEAndroid **WILL**crash.

- after hook "dlopen" function, caculate base_addr from return value of old dlopen (it's pointer to soinfo).

- support aarch64 (arm64-v8a)

ref:

&emsp;AllHookInOne : [https://github.com/boyliang/AllHookInOne.git]

&emsp;AllHookInOne description : [http://bbs.pediy.com/showthread.php?p=1328038]

&emsp;bionic : [https://android.googlesource.com/platform/bionic]


## 0x02 How To Build

#### Export android ndk path

> export -p PATH=$PATH:$ANDROID_NDK


#### Build

> make

> make clean

> make install  # copy libElfHook.so to jniLibs dir in Demo. 

#### or

> ndk-build NDK_PROJECT_PATH=. NDK_OUT=./objs NDK_LIBS_OUT=./bin APP_BUILD_SCRIPT=./Android.mk APP_PLATFORM=android-23 APP_ABI=arm64-v8a,armeabi-v7a APP_STL=stlport_static

**use NDK r11b**

## 0x03 How To Use

elf_module is a shared library or executable, elf_hooker is wrapper of hook function.

- bool elf_hooker::phrase_proc_maps()

phrase /proc/self/maps to create all elf modules have been loadded

- void elf_hooker::dump_module_list()

print all elf moudle's info, base addr and full path.

- void elf_hooker::set_prehook_cb( prehook_cb ):

set a callback function, which would be invoked before hooked. if it return false,  prehook_cb function like  this:

> bool prehook_cb(const char* module_name, const char* func_name);

> &emsp;module_name: the full filename of shared library or executable.

> &emsp;func_name: function name would be hooked.

- void elf_hooker::hook_all_modules(const char \*func_name, void \*pfn_new, void\*\* ppfn_old)

hook a function of all the modules, **MUST** call phrase_proc_maps() before hook_all_modules()

> &emsp;func_name: the name of function that will be hooked.

> &emsp;pfn_new: new function pointer

> &emsp;ppfn_old: return raw function pointer, ppfn_old **MUST NOT** be NULL

- bool elf_hooker::hook(elf_module \*module, const char\* func_name, void \*pfn_new, void \*\*ppfn_old)

hook a function of a single module.

> &emsp;module: pointer of elf_module.

> &emsp;other parameters is the same as hook_all_modules()
