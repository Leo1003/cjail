# cjail
---
## Introduction
cjail is a application jail for competitive programming and online judge

## Dependencies
You should check your system meets the dependencies before building it.

- Linux kernel 3.8+ (4.8+ is recommended)
- glibc 2.19+
- libseccomp 1.0.1+ (2.0+ is recommended)
- CMake 3.0.2+
- Criterion 2.3.3 (For running tests only)

## Build
cjail use CMake as build system. Install CMake first if you don't have it on your computer.  
We suggest you do an out-of-source build
```bash
mkdir build
cd build
cmake ..
make
```

## Notes
cjail is currently under development, the library API is unstable. 
So you should rebuild your application when you update the libcjail. 
Besides, there might be many bugs unfixed. 

Here is a list of the features that are not stable enough:

- Under testing:
	- Seccomp trace mode
	- In-box init process name concealing
	- In-box custom devfs mounting
- Not tested:
	- Seccomp for 32bits programs
	- Running on non-x86 machines
- Future changing:
	- Taskstats sockets
	- Mounting

---

## Command line

```text
Usage: cjail [OPTIONS...] [--] PROGRAM... [ARG...]
       cjail --help

  -c, --chroot=PATH             set the root path of the jail
  -d, --workingDir=PATH         change the working directory of the program
  -u, --uid=UID                 set the user of the program
  -g, --gid=GID                 set the group of the program
  -s, --cpuset=SET              set cpu affinity of the program with a list separated by ','
                                each entry should be <CPU> or <CPU>-<CPU>
      --share-net               not to unshare the net namespace while creating the jail
      --cgroup-root=PATH        change cgroup filesystem root path (default: /sys/fs/cgroup)
      --allow-root              allow uid or gid to be 0 (root)
  -q, --quiet                   not to print any message
  -v  --verbose                 print more details
  -h, --help                    show this help

 Resource Limit Options:
  -V, --limit-vss=SIZE          limit the memory space size can be allocated per process (KB)
  -C, --limit-core=SIZE         limit the core file size can be generated (KB)
  -Z, --limit-fsize=SIZE        limit the max file size can be created (KB)
  -P, --limit-proc=NUM          limit the process number in the jail
  -S, --limit-stack=SIZE        limit the stack size of one process (KB)
  -T, --limit-time=SEC          limit the total running time of the jail (sec)
  -M, --limit-rss=SIZE          limit the memory size can be used of the jail (KB)

 I/O Options:
  -i, --file-input=FILE         redirect stdin of the program to the file
  -o, --file-output=FILE        redirect stdout of the program to the file
  -r, --file-err=FILE           redirect stderr of the program to the file
  -I, --fd-input=FD             redirect stdin of the program to the file descriptor
  -O, --fd-output=FD            redirect stdout of the program to the file descriptor
  -R, --fd-err=FD               redirect stderr of the program to the file descriptor
      --preserve-fd             do not close file descriptors greater than 2

 Environment Variables Options:
  -e, --environ=ENV             set the environment variables of the program with a list separated by ';'
                                each entry should be <name>, !<name>, <name>=<value>
                                <name>        : try to inherit the environment variable from the parent process
                                !<name>       : unset the environment variable inheriting from the parent process
                                <name>=<value>: set the environment variable using giving name and value
  -E, --inherit-env             inherit all environment variables from the parent process

 Seccomp Options:
      --seccomp-cfg=FILE        specify seccomp rules to load
```

---

## Library call
cjail provide a interface to use the jail directly, without the need to call from command line interface.
For details, please view the documents generated by Doxygen
```bash
doxygen Doxyfile
```
