# ezinject
Modular binary injection framework

## Supported Architectures:
- Linux:
  - arm (arm+thumb)
  - aarch64
  - mips
  - x86
  - amd64
  
- Windows: x64
- FreeBSD: x86, amd64

## Supported C Libraries:
- Linux
  - glibc
  - uClibc (tested on ARM, MIPS)
  - Android (tested on Android 2.x - 10.x)
- FreeBSD (tested on FreeBSD 12)
- Windows
  - NT 6 (tested on Windows 10)

## How does it work

ezinject implements a single instrumentation primitive: remote syscalls

Remote syscalls are enough to take control of the target process.

We proceed as following:

- Create a shared memory map, that will hold the payload (use the pid of the target as key)
- Using remote syscalls, attach the shared memory in the target process
- Invoke the payload remotely, in shared memory.

The stack at entry will contain a pointer to the context, and a pointer to the function to call.
- The payload pops the parameters and the function to call from the stack, then calls the function in C (thus emitting a proper call with a stack frame)
- The payload implementation creates a pthread cond, opens the target library and awaits for completion.
- The ezinject's crt, linked in the library, is invoked as part of `__attribute__((constructor))`
- The crt attaches to shared memory, then creates a local copy of the context (including arguments).
- The crt prepares argv, then creates a new thread to run `lib_preinit` and `lib_main` functions
- The user library is invoked. It can call any function inside the target, replace or hook functions (with libhooker in userland)
