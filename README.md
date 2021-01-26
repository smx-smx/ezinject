# ezinject
Modular binary injection framework

## How does it work

ezinject implements a single instrumentation primitive: remote syscalls

Remote syscalls are enough to take control of the target process.

We proceed as following:

- Create a shared memory map, that will hold the payload (use the pid of the target as key)
- Create a semaphore, and set its value to 1. It will be used as a signal (use the pid of the target as key)
- Using remote syscalls, attach the shared memory in the target process (shmget + shmat)
- Using remote syscalls, call clone() in the target process (while sharing as much as we can from the parent - see clone flags).
The stack of the cloned process will contain a pointer to the payload, and a pointer to the parameters.
- The payload pops the parameters from stack, then calls glibc's internal dlopen, opening the target library
- The ezinject's crt, linked in the library, is invoked as part of `__attribute__((constructor))`
- The crt attaches to shared memory, then copies parameters locally (including arguments).
- The crt signals ezinject that shared memory can be freed, by decrementing the semaphore.
- The crt prepares argv, then calls the main function
- The user library is invoked. It can call any function inside the target, replace or hook functions (with libhooker in userland)

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
