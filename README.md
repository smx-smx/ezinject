# ezinject
Modular binary injection framework [![Join us on Discord](https://img.shields.io/static/v1?link=https://discord.gg/wsZhBCEJsX&message=Join%20Discord&logo=discord&style=flat&color=107090&labelColor=5E5E5E&label=&logoColor=white)](https://discord.gg/wsZhBCEJsX)

## What is ezinject
ezinject is a **lightweight** and **flexible** binary injection framework.
it can be thought as a lightweight and less featured version of frida.

It's main and primary goal is to load a user module (.dll, .so, .dylib) inside a target process.
These modules can augment ezinject by providing additional features, such as hooks, scripting languages, RPC servers, and so on.
They can also be written in multiple languages such as C, C++, Rust, etc... as long as the ABI is respected.

**NOTE**: ezinject core is purposedly small, and only implements the "kernel-mode" (debugger) features it needs to run the "user-mode" program, aka the user module.

It requires **no dependencies** other than the OS C library (capstone is optionally used only by user modules)

Porting ezinejct is **simple**: No assembly code is required other than a few inline assembly statements, and an abstraction layer separates multiple OSes implementations.

As proof, it has been ported and battle-tested on a wild variety of Linux devices such as:

- Asus DSL-N55U D1, a Mips BE DSL modem running uClibc and Linux 2.6
- ADB/DLink DVA-5592, an ARM v7 FPU-less xDSL modem running uClibc and Linux 3.0
- Samsung GT-i9003 (latona), an Android 2.3 smartphone running Linux 2.6
- Samsung GT-i9070 (janice), running Android 4
- Samsung GT-i9300 (smdk4x12), running Android 7
- pocophone F1 (beryllium), running Android 10
- TomTom GO 910, a standalone GPS nav running glibc 2.3 and Linux 2.6

as well as wildly different (both POSIX and non-POSIX OSes) such as

- Windows
- FreeBSD
- Darwin (macOS)

## Example of modules:
- hooks example ([libdummy](https://github.com/smx-smx/ezinject/tree/master/samples/dummy))
- run Python scripts ([pyloader](https://github.com/smx-smx/ezinject/tree/master/samples/pyloader))
- run PHP scripts ([php](https://github.com/smx-smx/ezinject/tree/master/samples/php))
- run .NET programs ([mono](https://github.com/smx-smx/ezinject/tree/master/samples/mono), [dotnetcore](https://github.com/smx-smx/ezinject/tree/master/samples/dotnetcore), [EzDotNet](https://github.com/smx-smx/EzDotnet))
- turn the remote process into an RPC ([ezinject-webapi](https://github.com/smx-smx/))

and so on...

## Modules ABI
Shared modules must implement the following 2 functions:

#### `int lib_preinit(struct injcode_user *user)`
This function is provided to let the user control the module lifecycle.

For example, by setting `user->persist` to 1, the module can be kept persistent in memory once `lib_main` returns.

This function should always return 0 to signal success.

#### `int lib_main(int argc, char *argv[])`
It works just like a typical `main` function in C.

`argv[0]` holds the name of the module, while `argv[1]` onwards are user arguments that you passed to the `ezinject` binary (they are passed to the module as user supplied arguments)

**NOTE**: `lib_main` is executed synchronously, and `ezinject` will not complete until this function has returned. If you need to perform background work, you will need to **make a copy of `argv`** (important, as it will be freed upon return) and start a new thread.
See the php module for an example


## Supported Architectures:
- Linux:
  - arm (arm+thumb)
  - aarch64
  - mips
  - x86
  - amd64

- Windows: x86, x64
- FreeBSD: x86, x64
- Darwin: x64

## Supported C Libraries:
- Linux
  - glibc
  - uClibc (tested on ARM, MIPS)
  - Android (tested on Android 2.x - 10.x)
- FreeBSD (tested on FreeBSD 12)
- Windows
  - NT 6 (tested on Windows 10)
- Darwin (tested on macOS 11)

## How does it work

ezinject implements a single instrumentation primitive: remote calls

We proceed as following:

- Create a remote memory segment that will hold the payload
  - If using shared memory, use remote syscalls to attach the shared memory in the target process
- Invoke the payload remotely.

The stack at entry will contain a pointer to the context, and a pointer to the function to call.
- The payload pops the parameters and the function to call from the stack, then calls the function in C (thus emitting a proper call with a stack frame)
- The payload implementation creates a mutex/event, then opens the target library and awaits for the thread to be created.
- The ezinject's crt (linked in the library) creates a local copy of the context, then creates a new thread.
- The crt signals that the thread is ready to be awaited
- The newly created thread prepares argv, then invokes `lib_preinit` and `lib_main` functions in the library
- The user code is invoked. It can call any function inside the target, replace or hook functions (with libhooker as part of the CRT, in userland)

## Build

The following is an example on Debian and derivates, needs to be adjusted for each platform.

1. Install dependencies
- build-essential
- cmake
- libcapstone-dev
- pkg-config

2. Build the project
```sh
./build.sh
```

## Sample usage

### Linux .so injection

On Terminal 1
```sh
$ cd build/samples/dummy
$ ./target
```

On Terminal 2
```sh
$ cd build
$ sudo ./ezinject `pidof target` samples/dummy/libdummy.so
```

Expected output
```text
return1() = 1
```
changes to
```
return1() = 13370
```

### Python injection

```sh
echo "print('hello ' * 3 + 'from python')" > hello.py
export EZPY=`python -c "import sys; import os; print(os.pathsep.join(sys.path))"`
echo "python path: $EZPY"
```

Find libpython:
```
find /usr/lib -name "libpython*"
```

Put correct libpython and paths in example below:
```
sudo ./ezinject `pidof target` samples/pyloader/libpyloader.so /usr/lib/x86_64-linux-gnu/libpython2.7.so.1 /usr/lib/python2.7 "$EZPY" hello.py
```

## Credits
This project has initially been created for the openlgtv community, of which i'm a member. It has since evolved to be a generic tool

Thanks to all members of the [openlgtv](https://github.com/openlgtv) and [webosbrew](https://github.com/webosbrew) community for supporting the development by adopting and testing ezinject.

Special thanks to:
- [irsl](https://github.com/irsl), for the initial work on libhooker, which inspired me to get involved
- [mudkip908](https://github.com/mudkip908), for the preliminar ezinject proof of concept and code review

If you would like to support the ezinject development, you can
- use it and spread the word
- submit issues, suggestions, or pull requests
- if you feel like, you can donate to me: <a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=K58G5YC9M76QN"><img src="https://www.paypalobjects.com/en_US/i/btn/btn_donate_LG.gif" alt="[paypal]" /></a>
