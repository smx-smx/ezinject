# ezinject
Modular binary injection framework [![Join us on Discord](https://img.shields.io/static/v1?link=https://discord.gg/wsZhBCEJsX&message=Join%20Discord&logo=discord&style=flat&color=107090&labelColor=5E5E5E&label=&logoColor=white)](https://discord.gg/wsZhBCEJsX)

## Supported Architectures:
- Linux:
  - arm (arm+thumb)
  - aarch64
  - mips
  - x86
  - amd64
  
- Windows: x64
- FreeBSD: x86, amd64
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

- Create a remote memory segment (via shared memory or remote allocation), that will hold the payload
  - If using shared memory, use remote syscalls to attach the shared memory in the target process
- Invoke the payload remotely, in shared memory.

The stack at entry will contain a pointer to the context, and a pointer to the function to call.
- The payload pops the parameters and the function to call from the stack, then calls the function in C (thus emitting a proper call with a stack frame)
- The payload implementation creates a mutex/event, then opens the target library and awaits for the thread to be created.
- The ezinject's crt (linked in the library) creates a local copy of the context, then creates a new thread.
- The crt signals that the thread is ready to be awaited
- The newly created thread prepares argv, then invokes `lib_preinit` and `lib_main` functions in the library
- The user code is invoked. It can call any function inside the target, replace or hook functions (with libhooker in userland)

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

```
echo "print('hello ' * 3 + 'from python');" > hello.py
export EZPY=`python -c "import sys; print(':'.join(sys.path))"`
echo "python path: $EZPY"
```

Find libpython:
```
find /usr/lib -name "libpython*"
```

Put correct libpython and paths in example below:
```
sudo ./ezinject `pidof target` samples/pyloader/libpyloader.so /usr/lib/x86_64-linux-gnu/libpython2.7.so.1 /usr/lib/python2.7 $EZPY hello.py
```
