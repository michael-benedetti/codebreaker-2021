# Task 6

In task 5 we identified `make` as our malicious file.  For task 6 we will be digging into the malicious `make` sample to identify the IP of the LP it sends data to, the public key of the LP, and the version number of the malware.

Let's pull `make` from the image so we can start reverse engineering it in Ghidra.

```bash
$ docker cp frosty_beaver:/usr/bin/make .
```

Now that we have a local copy of `make`, let's fire up Ghidra, start a new project, and import the artifact.  Once imported, launch CodeBrowser by double clicking the newly imported file.  When prompted to anaylze the binary, go ahead and select `yes`, keep the default options, and select `Analyze`.

Once the binary is loaded and the analyzers have finished running, we can jump to the main function by pressing `g` and entering `main` then hitting `OK`.  We see the following in the decompilation window:

```c
int main(int argc,char **argv)

{
  int iVar1;
  char *pcVar2;
  
  gitGrabber();
  pcVar2 = jlwcaabvzqrqc(0xe);
  *argv = pcVar2;
  iVar1 = execvp(*argv,argv);
  return iVar1;
}
```

At first glance, we can see a call to the function `gitGrabber` followed by a call to the oddly named `jlwcaabvzqrqc`.  Whatever is returned from this function is then passed to `execvp`, and then `main` returns.  To help us reason about the binary, it is important that as we identify new functionality, we appropriately label it.  An approach to reverse engineering complex binaries that has worked for me thus far is to combine static analyis in Ghidra with dynamic analysis in gdb.  This way, as we encounter function calls, we can observe the real behavior and return values to help identify what it's doing.  Just don't go running strange binaries if you don't have a reliable sandbox environment to run them in.

Before we fire up gdb, let's take a look at some of the file characteristics:

```bash
$ file make
make: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-x86_64.so.1, with debug_info, not stripped
$ ldd make
        linux-vdso.so.1 (0x00007ffe711ff000)
        libgit2.so.1.1 => /lib/libgit2.so.1.1 (0x00007f783ce07000)
        libstdc++.so.6 => /lib/x86_64-linux-gnu/libstdc++.so.6 (0x00007f783cc25000)
        libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007f783cc0a000)
        libc.musl-x86_64.so.1 => /lib/libc.musl-x86_64.so.1 (0x00007f783cb72000)
        libssl.so.1.1 => /lib/x86_64-linux-gnu/libssl.so.1.1 (0x00007f783cadf000)
        libcrypto.so.1.1 => /lib/x86_64-linux-gnu/libcrypto.so.1.1 (0x00007f783c809000)
        libpcre.so.1 => /lib/libpcre.so.1 (0x00007f783c7ab000)
        libhttp_parser.so.2.9 => /lib/x86_64-linux-gnu/libhttp_parser.so.2.9 (0x00007f783c79f000)
        libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007f783c783000)
        libssh2.so.1 => /lib/x86_64-linux-gnu/libssh2.so.1 (0x00007f783c754000)
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f783c605000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f783c413000)
        /lib/ld-musl-x86_64.so.1 => /lib64/ld-linux-x86-64.so.2 (0x00007f783cfb4000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f783c3ee000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f783c3e8000)
        libgcrypt.so.20 => /lib/x86_64-linux-gnu/libgcrypt.so.20 (0x00007f783c2ca000)
        libgpg-error.so.0 => /lib/x86_64-linux-gnu/libgpg-error.so.0 (0x00007f783c2a7000)
```

We can see we are dealing with a 64 bit binary that is dynamically linked to a significant number of libraries.  It is unlikely that our environment has everything it needs to properly execute this binary, however we already have an environment available to us that hopefully does have everything it needs - the docker container we pulled the binary from.

In our container's root shell, we first need to ensure gdb and curl are installed:

```bash
apk add gdb curl
```

Now, feel free to install any gdb enhancements you prefer.  For this challenge, I'll install [gef](https://gef.readthedocs.io/en/master):

```bash
wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh
```

Fire up gef and run the start command, which will set a breakpoint at main and run the binary:

```bash
# gdb make
gef➤  start
```

Before we go any further, we'll want to align the address spaces between gdb and Ghidra.  Within gdb, run `vmmap`:

```bash
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x000055cafa5b0000 0x000055cafa5b9000 0x0000000000000000 r-- /usr/bin/make
0x000055cafa5b9000 0x000055cafa616000 0x0000000000009000 r-x /usr/bin/make
0x000055cafa616000 0x000055cafa64f000 0x0000000000066000 r-- /usr/bin/make
0x000055cafa650000 0x000055cafa653000 0x000000000009f000 r-- /usr/bin/make
0x000055cafa653000 0x000055cafa654000 0x00000000000a2000 rw- /usr/bin/make
...
```

The first address we see is the base address that we are interested in.  Go ahead and copy that and head back over to Ghidra.  Select `Window -> Memory Map`, click the `Home` icon in the top right, enter the address we just copied, and click `ok`.  Our addresses should now be aligned which will help us in our analysis.

Back in gdb, we can begin stepping through the program one instruction at a time with `ni`, and following function calls that are interesting with `si`.  If we step into `gitGrabber` and then step into the function call at `0x55cafa5ba288`, we find ourselves in the following disassembled function:

```bash
gef➤  disass weuztpqjygefp
Dump of assembler code for function weuztpqjygefp():
=> 0x0000556f11a61c9f <+0>:     push   rbp
   0x0000556f11a61ca0 <+1>:     mov    rbp,rsp
   0x0000556f11a61ca3 <+4>:     sub    rsp,0x10
   0x0000556f11a61ca7 <+8>:     mov    DWORD PTR [rbp-0xc],0xffffffff
   0x0000556f11a61cae <+15>:    mov    edi,0x6
   0x0000556f11a61cb3 <+20>:    call   0x556f11ab7dec <_Z13jlwcaabvzqrqci>
   0x0000556f11a61cb8 <+25>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000556f11a61cbc <+29>:    mov    rax,QWORD PTR [rbp-0x8]
   0x0000556f11a61cc0 <+33>:    mov    edx,0x1a4
   0x0000556f11a61cc5 <+38>:    mov    esi,0xc1
   0x0000556f11a61cca <+43>:    mov    rdi,rax
   0x0000556f11a61ccd <+46>:    mov    eax,0x0
   0x0000556f11a61cd2 <+51>:    call   0x556f11a61700 <open@plt>
   0x0000556f11a61cd7 <+56>:    mov    DWORD PTR [rbp-0xc],eax
   0x0000556f11a61cda <+59>:    mov    edi,0x6
   0x0000556f11a61cdf <+64>:    call   0x556f11ab7d49 <_Z13cikyvjbgzkirti>
   0x0000556f11a61ce4 <+69>:    mov    eax,DWORD PTR [rbp-0xc]
   0x0000556f11a61ce7 <+72>:    leave
   0x0000556f11a61ce8 <+73>:    ret
```

This corresponds to the following decompilation in Ghidra:

```c
int weuztpqjygefp(void)

{
  int iVar1;
  char *__file;
  int fd;
  char *lockfile;
  
  __file = jlwcaabvzqrqc(6);
  iVar1 = open(__file,0xc1,0x1a4);
  cikyvjbgzkirt(6);
  return iVar1;
}
```

This function appears to be calling a familiar function - `jlwcaabvzqrqc` - and then calling `open` on the result.  We first saw `jlwcaabvzqrqc` in `main` with an argument of `0xe`, and now we see it with an argument of `6`.  Let's continue to `0x0000556f11a61cb3` and observe the return from `jlwcaabvzqrqc`.

```bash
gef➤  br *0x0000556f11a61cb3
Breakpoint 1 at 0x556f11a61cb3: file gitGrabber.cpp, line 29.
gef➤  c
gef➤  ni
gef➤  telescope $rax 1
0x00007f2f5d2f0b14│+0x0000: "/tmp/.gglock"       ← $rax
```

After stepping over the call to `jlwcaabvzqrqc(6)`, we see the result was the string `/tmp/.gglock`.  Let's take a closer look at `jlwcaabvzqrqc`.  Navigating to the function in Ghidra, we see a fairly large function with a long switch statement.  The switch statement is based off the passed in argument:

```c
  switch(stringId) {
  case 1:
                    /* try { // try from 0015fe7c to 0016032f has its CatchHandler @ 001603f9 */
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::assign
              ((char *)&ciphertext,(ulong)&DAT_55cafa61a5fc);
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::assign
              ((char *)&nonce,(ulong)&DAT_55cafa61a60f);
    break;
  case 2:
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::assign
              ((char *)&ciphertext,(ulong)&DAT_55cafa61a628);
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::assign
              ((char *)&nonce,(ulong)&DAT_55cafa61a640);
    break;
  case 3:
  ...
  ...
```

Each case seems to be assigning a ciphertext and nonce, which seems to indicate that we are dealing with some encrypted strings.  Beyond the switch statement, we see a call to `whbdpevbewdde`.  Inspecting this function yields the following in Ghidra:

```c
void whbdpevbewdde(string *ciphertext,string *nonce,char *buffer)

{
  long lVar1;
  size_t __n;
  void *__src;
  ulong uVar2;
  long in_FS_OFFSET;
  size_t i;
  string result;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  crypto_secretbox_xsalsa20poly1305_ref_open
            ((basic_string *)&result,(basic_string *)ciphertext,(basic_string *)nonce);
  __n = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length();
  __src = (void *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::
                  c_str();
  memcpy(buffer,__src,__n);
  buffer[0x3f] = '\0';
  i = 0;
  while( true ) {
    uVar2 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length();
    if (uVar2 <= i) break;
    i = i + 1;
  }
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&result);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

This function takes in a ciphertext, nonce, and what appears to be an output buffer.  It calls `crypto_secretbox_xsalsa20poly1305_ref_open`, which a quick google gives a handful of results indicating that this is indeed a decryption function.  Let's experiment with different arguments in gdb and see what the results are.  We can start with passing the value we saw in `main`:

```bash
gef➤  call jlwcaabvzqrqc(0xe)
$1 = 0x7f2f5d2f0b74 "ninja"
gef➤  call jlwcaabvzqrqc(1)
$2 = 0x7f2f5d2f0bd4 "os"
gef➤  call jlwcaabvzqrqc(2)
$3 = 0x7f2f5d2f0c34 "version"
gef➤  call jlwcaabvzqrqc(3)
$4 = 0x7f2f5d2f0c94 "username"
gef➤  call jlwcaabvzqrqc(4)
$5 = 0x7f2f5d2f0cf4 "timestamp"
gef➤  call jlwcaabvzqrqc(5)
$6 = 0x7f2f5d2f0d54 "unknown"
gef➤  call jlwcaabvzqrqc(6)
$7 = 0x7f2f5d2f0db4 "/tmp/.gglock"
gef➤  call jlwcaabvzqrqc(7)
$8 = 0x7f2f5d2f0e14 "/usr/local/src/repo"
```

At this point, we can be fairly confident that `jlwcaabvzqrqc` is a function that decrypts strings associated with the integeer argument passed in.  Let's update the label to `decryptString` and check out where it is referenced in the binary.  After a bit of poking around the references list, we find the following interesting calls:

```bash
ip_00 = decryptString(0x13);
pubKey = decryptString(0x12);
version_00 = decryptString(0x11);
```

Let's head back to gdb and call our function with these values:

```bash
gef➤  call jlwcaabvzqrqc(0x13)
$9 = 0x7f2f5d2f0e74 "198.51.100.233"
gef➤  call jlwcaabvzqrqc(0x12)
$10 = 0x7f2f5d2f0ed4 "\023\260H~0\230\240\260\n\226Kv\376\205}O\350H\002\247\337Q\246y\252k`\200\351w\205\024"
gef➤  call jlwcaabvzqrqc(0x11)
$11 = 0x7f2f5d2f0f34 "3.3.3.3-IZT"
```

The first and last call look very promising - we may have just found our ip and version.  The second call doesn't look quite right, so lets observe the data, which now exists at `0x7f2f5d2f0ed4`, in another format:

```bash
gef➤  x/32bx 0x7f2f5d2f0ed4
0x7f2f5d2f0ed4: 0x13    0xb0    0x48    0x7e    0x30    0x98    0xa0    0xb0
0x7f2f5d2f0edc: 0x0a    0x96    0x4b    0x76    0xfe    0x85    0x7d    0x4f
0x7f2f5d2f0ee4: 0xe8    0x48    0x02    0xa7    0xdf    0x51    0xa6    0x79
0x7f2f5d2f0eec: 0xaa    0x6b    0x60    0x80    0xe9    0x77    0x85    0x14
```

Now we have what looks like a potential usable 32 byte public key.  We just need to merge the bytes together:

```
13b0487e3098a0b00a964b76fe857d4fe84802a7df51a679aa6b6080e9778514
```

Submitting these as our answer gets us a pass on task 6!