#cjail
---
##Introduction
cjail is a application jail for competitive programming and online judge

##Build
cjail use CMake as build system. Install CMake first if you don't have it on your computer.
We suggest you do an out-of-source build
```bash
mkdir build
cd build
cmake ..
make
```

##Library call
cjail provide a interface to use the jail directly, without the need to compile the command.
```c
int cjail_exec(struct cjail_para *para, struct cjail_result *result);
```
####Parameter
**para**: Configures to change the jail behaviors.
**result**: After a successful execution, the results and stats of the process will be filled in it.
####Return value
Return 0 if successfully execute the specific process, otherwise, the execution is failed.

##Struct
```c
struct cjail_para;
```
- **argv** ^char**^: The arguments of the process to be executed.
- **environ** ^char**^: The environment variables for the process. Each string should be "[name]=[val]".
- **chroot** ^char*^: The path to chroot, and after a successful chroot will automatically chdir to new root. Set to NULL to disable chroot.
- **workingDir** ^char*^: The working directory of the process. Note that this path is relative to the new root.
Set to NULL will make the working directory unchanged.
- **uid** ^uid_t^: The uid of the process. 
- **gid** ^gid_t^: The gid of the process. 
- **redir_input** ^char*^: The file path to redirect to the standard input(fd 0)
- **redir_output** ^char*^: The file path to redirect to the standard output(fd 1)
- **redir_err** ^char*^: The file path to redirect to the standard error(fd 2)
- **fd_input** ^int^: The fd number to be duplicated to the standard input(fd 0). Note that this option will override **redir_input**. Set to 0 to disable this configure.
- **fd_output** ^int^: The fd number to be duplicated to the standard output(fd 1). Note that this option will override **redir_output**. Set to 0 to disable this configure.
- **fd_err** ^int^: The fd number to be duplicated to the standard error(fd 2). Note that this option will override **redir_err**. Set to 0 to disable this configure.
- **prevervefd** ^unsigned int^: Set to 1 to keep fd above 3 opening. **Use this carefully!!** Note that the fd used by cjail will close on executing the process.
- **sharenet** ^unsigned int^: Set to 1 to share the same network namespace with the calling process. **Use this carefully!!**


**Unfinished......**
