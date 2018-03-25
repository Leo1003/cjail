# cjail
---
## Introduction
cjail is a application jail for competitive programming and online judge

## Build
cjail use CMake as build system. Install CMake first if you don't have it on your computer.
We suggest you do an out-of-source build
```bash
mkdir build
cd build
cmake ..
make
```

---

## Library call
cjail provide a interface to use the jail directly, without the need to call the command.

---

```c
void cjail_para_init(struct cjail_para *para);
```
Initialize cjail_para struct
#### Parameters
struct cjail_para **para**: the parameter struct to be initialized.

---

```c
int cjail_exec(const struct cjail_para *para, struct cjail_result *result);
```
Execute a process in the jail
#### Parameters
struct cjail_para **para**: Configures to change the jail behaviors.
struct cjail_result **result**: After a successful execution, the results and stats of the process will be filled in it.
#### Return value
Return 0 if successfully executed the specific process, otherwise, the execution is failed.

---

```c
int cpuset_tostr(const cpu_set_t* cpuset, char *str, size_t len);
```
Convert cpu_set_t to human readable format
#### Parameters
cpu_set_t* **cpuset**: Cpuset to be converted
char* **str**: Output string
size_t **len**: The buffer size of the string (including the terminating null byte)
#### Return value
Return the length of the string (excluding the terminating null byte) if successfully converted. Return -1 if any error occurred.

---

```c
int cpuset_parse(const char *str, cpu_set_t *cpuset);
```
Convert human readable format to cpu_set_t
#### Parameters
const char* **str**: Null-terminated string to be converted
cpu_set_t* **cpuset**: Output cpuset struct
#### Return value
Return 0 if successfully converted. Return -1 if any error occurred.
#### NOTE
A legal string should only contain numbers, ',', and '-'. It must not have any space in it; otherwise, the convertion would error. Each cpu number should be separated by ','. You can also use '-' to represent continous cpu numbers, like "0,1-3,5,9-10".


---
## Struct
```c
struct cjail_para;
```
- char** **argv**: The arguments of the process to be executed.
- char** **environ**: The environment variables for the process. Each string should be "[name]=[val]".
- char* **chroot**: The path to chroot, and after a successful chroot will automatically chdir to new root. Set to NULL to disable chroot.
- char* **workingDir**: The working directory of the process. Note that this path is relative to the new root.
Set to NULL will make the working directory unchanged.
- uid_t **uid**: The uid of the process.
- gid_t **gid**: The gid of the process.
- char* **redir_input**: The file path to redirect to the standard input(fd 0)
- char* **redir_output**: The file path to redirect to the standard output(fd 1)
- char* **redir_err**: The file path to redirect to the standard error(fd 2)
- int **fd_input**: The fd number to be duplicated to the standard input(fd 0). Note that this option will override **redir_input**. Set to 0 to disable this configure.
- int **fd_output**: The fd number to be duplicated to the standard output(fd 1). Note that this option will override **redir_output**. Set to 0 to disable this configure.
- int **fd_err**: The fd number to be duplicated to the standard error(fd 2). Note that this option will override **redir_err**. Set to 0 to disable this configure.
- unsigned int **prevervefd**: Set to 1 to keep fds above 3 opening. **Use this carefully!!** Note that the fds used by cjail will close on executing the process.
- unsigned int **sharenet**: Set to 1 to share the same network namespace with the calling process. **Use this carefully!!**
- cpu_set_t* **cpuset**: Limit the cpus which the process can run on with this set.
- long long **rlim_as**: Limit the maximum size(KB) of availble memory of the process. Set to 0 to disable this limit.
- long long **rlim_core**: Limit the maximum size(KB) of core dump. Set to 0 to disable coredump generation. Set to negative value to disable this limit.
- long long **rlim_fsize**: Limit the maximum file size(KB) of a file that can be created. Set to 0 to disable this limit.
- long long **rlim_proc**: Limit the maximum processes can be created. Set to 0 to disable this limit.
- long long **rlim_stack**: Limit the maximum size(KB) of the stack of the process. Set to 0 to disable this limit.
- timeval* **lim_time**: Limit the running time. If the time is exceeded, all of the processes in the namespace will be killed.
- char* **cgroup_root**: Change the cgroup filesystem root path(outside the chroot jail). Default: "/sys/fs/cgroup"
- long long **cg_rss**: Limit the maximum size(KB) of memory of the cgroup. Set to 0 to disable this limit.

---

```c
struct cjail_result;
```
- struct taskstats **stats**: The resource stats of the child process.
- siginfo_t **info**: The child process's return status.
- struct timeval **time**: The total execution time of the container.

