# Task 8

For task 8, we will be going back and taking a closer look at the pcap data provided with [task 1](../task-1/). Our goal
is to parse the pcap data and decrypt LP communication sessions to retrieve UUIDs of the associated clients.

## Understanding more about the encryption techniques

To accomplish this task, we will need to continue reverse engineering the malicious `make` binary to better understand
how messages are being encrypted. Recalling that the function `ywiuyvacoaplj` was handling the socket connection,
initial crypt negotiation, and construction of the session init message, we can continue where we left off and discover
that the function is also building upload messages, and a session termination message. Once all of the messages have
been constructed, the program proceeds to the function `rhzahjabrnntl`. Let's take a look at this function:

```c
string * rhzahjabrnntl(string *__return_storage_ptr__,string *session_key,void *buffer,size_t size)

{
  long lVar1;
  long in_FS_OFFSET;
  string *finalMessage;
  allocator<char> local_d1;
  size_t bodyLen;
  string message;
  string nonce;
  string ciphertext;
  string length_headerStr;
  basic_string<char,std--char_traits<char>,std--allocator<char>> local_48;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  std::allocator<char>::allocator();
                    /* try { // try from 0015a40b to 0015a40f has its CatchHandler @ 0015a511 */
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string
            ((char *)&message,(ulong)buffer,(allocator *)size);
  std::allocator<char>::~allocator(&local_d1);
                    /* try { // try from 0015a42e to 0015a432 has its CatchHandler @ 0015a575 */
  generateRandomBytes(&nonce,0x18);
                    /* try { // try from 0015a44f to 0015a453 has its CatchHandler @ 0015a561 */
  crypto_secretbox_xsalsa20poly1305_ref
            ((basic_string *)&ciphertext,(basic_string *)&message,(basic_string *)&nonce);
  lVar1 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length();
  bodyLen = lVar1 + 0x18;
                    /* try { // try from 0015a47c to 0015a480 has its CatchHandler @ 0015a550 */
  lengthHeader(&length_headerStr,bodyLen);
                    /* try { // try from 0015a496 to 0015a49a has its CatchHandler @ 0015a53f */
  std::operator+<char,std--char_traits<char>,std--allocator<char>>
            (&local_48,
             (basic_string<char,std--char_traits<char>,std--allocator<char>> *)&length_headerStr,
             (basic_string<char,std--char_traits<char>,std--allocator<char>> *)&nonce);
                    /* try { // try from 0015a4b0 to 0015a4b4 has its CatchHandler @ 0015a52e */
  std::operator+<char,std--char_traits<char>,std--allocator<char>>
            ((basic_string<char,std--char_traits<char>,std--allocator<char>> *)
             __return_storage_ptr__,&local_48,
             (basic_string<char,std--char_traits<char>,std--allocator<char>> *)&ciphertext);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&local_48);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&length_headerStr);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&ciphertext);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&nonce);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&message);
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return __return_storage_ptr__;
}
```

This function appears to be handling the encryption of the generated messages. It first generates a random `24` byte
nonce, and then calls `crypto_secretbox_xsalsa20poly1305_ref` to encrypt the passed in message. It then generates a
length header, and produces a final message with the following format:

```
[LENGTH_HEADER][NONCE][CIPHERTEXT]
```

So we know that our messages will be encrypted, but what the Ghidra decompilation does not inform us of is the
encryption key. Let's take another look at the disassembly near the call to the `crypto_secretbox` function:

```nasm
   0x00005555555ae433 <+141>:   lea    rax,[rbp-0x80]
   0x00005555555ae437 <+145>:   mov    rcx,QWORD PTR [rbp-0xe0]
   0x00005555555ae43e <+152>:   lea    rdx,[rbp-0xa0]
   0x00005555555ae445 <+159>:   lea    rsi,[rbp-0xc0]
   0x00005555555ae44c <+166>:   mov    rdi,rax
   0x00005555555ae44f <+169>:   call   0x5555555b4e20 <_Z37crypto_secretbox_xsalsa20poly1305_refRKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES6_S6_>
```

We can see four arguments are being prepped for the call, however the Ghidra decompilation only shows us three. Let's
break just before this call in gdb to observe what is being passed in for the init message - NOTE: be sure to restart
your netcat listener and ensure `/tmp/.gglock` is removed as described in [task 7](../task-7/):

```bash
gef➤  br *(rhzahjabrnntl+169)
gef➤ c

_Z37crypto_secretbox_xsalsa20poly1305_refRKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES6_S6_ (
   $rdi = 0x00007fffffffe730 → 0x0000000000000002,
   $rsi = 0x00007fffffffe6f0 → 0x00007ffff77fcd40 → 0x0200006e2acb5d11,
   $rdx = 0x00007fffffffe710 → 0x00007ffff77fe5b0 → 0x9b1fce94706615ef,
   $rcx = 0x00007fffffffe900 → 0x00007ffff77fddf0 → 0x8552166ec93db987,
   $r8 = 0x00007ffff77fe5a8 → 0x002e770000000000
)
```

Here we can see the first argument is a placeholder for the output of the encryption function.  `RSI`, our second
argument, at initial glance, appears to be the plaintext init message. Examining the contents of `RDX` - our third
argument - reveals that it is likely the `24` byte nonce. The fourth argument appears to be `32` somewhat random looking
bytes. This is likely our encryption key.

### Identifying the key generation algorithm

Now that we see where our key is being utilized, we need to figure out where it is coming from. Working back in Ghidra,
in `ywiuyvacoaplj` we see the following call to `fpToK`:

```c
fpToK(&session_key,username,version_00,tv.tv_sec);
```

Here's the decompilation of `fpToK`:

```c
string * fpToK(string *__return_storage_ptr__,char *username,char *version,time_t timestamp)

{
  long lVar1;
  basic_ostream *pbVar2;
  size_t len;
  BYTE *data;
  long in_FS_OFFSET;
  string *session_key;
  allocator<char> local_2a9;
  string lowecaseUser;
  string versionShort;
  string key_str;
  SHA256_CTX ctx;
  stringstream ss;
  basic_ostream abStack456 [384];
  BYTE buf [32];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  std::__cxx11::basic_stringstream<char,std::char_traits<char>,std::allocator<char>>::
  basic_stringstream();
                    /* try { // try from 001597f9 to 001597fd has its CatchHandler @ 00159a0f */
  xvbryrtttcahm(&lowecaseUser,username);
  std::allocator<char>::allocator();
                    /* try { // try from 0015982d to 00159831 has its CatchHandler @ 001599b0 */
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string
            ((char *)&versionShort,(ulong)version,(allocator *)0x7);
  std::allocator<char>::~allocator(&local_2a9);
                    /* try { // try from 00159859 to 001598be has its CatchHandler @ 001599ec */
  pbVar2 = std::operator<<(abStack456,(basic_string *)&lowecaseUser);
  pbVar2 = std::operator<<(pbVar2,"+");
  pbVar2 = std::operator<<(pbVar2,(basic_string *)&versionShort);
  pbVar2 = std::operator<<(pbVar2,"+");
  std::basic_ostream<char,std::char_traits<char>>::operator<<
            ((basic_ostream<char,std::char_traits<char>> *)pbVar2,timestamp);
  std::__cxx11::basic_stringstream<char,std::char_traits<char>,std::allocator<char>>::str();
                    /* try { // try from 001598c9 to 0015991c has its CatchHandler @ 001599d8 */
  nmcnykqmzdnmy(&ctx);
  len = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length();
  data = (BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str
                           ();
  afrjzyetfzmdk(&ctx,data,len);
  vzanrtdpzfwrd(&ctx,buf);
  std::allocator<char>::allocator();
                    /* try { // try from 00159949 to 0015994d has its CatchHandler @ 001599c4 */
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string
            ((char *)__return_storage_ptr__,(ulong)buf,(allocator *)0x20);
  std::allocator<char>::~allocator(&local_2a9);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&key_str);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&versionShort);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&lowecaseUser);
  std::__cxx11::basic_stringstream<char,std::char_traits<char>,std::allocator<char>>::
  ~basic_stringstream((basic_stringstream<char,std::char_traits<char>,std::allocator<char>> *)&ss);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return __return_storage_ptr__;
}
```

Initial analysis reveals that the passed in username, shortened version, and timestamp are being concatenated with `+`
character delimiters. Three additional interesting calls are then executed:

```c
  nmcnykqmzdnmy(&ctx);
  len = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length();
  data = (BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str
                           ();
  afrjzyetfzmdk(&ctx,data,len);
  vzanrtdpzfwrd(&ctx,buf);
```

And the decompilation for each:

```c
void nmcnykqmzdnmy(SHA256_CTX *ctx)

{
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
  return;
}
```

```c
void afrjzyetfzmdk(SHA256_CTX *ctx,BYTE *data,size_t len)

{
  WORD i;
  
  for (i = 0; i < len; i = i + 1) {
    ctx->data[ctx->datalen] = data[i];
    ctx->datalen = ctx->datalen + 1;
    if (ctx->datalen == 0x40) {
      dfbrevgdvcrca(ctx,ctx->data);
      ctx->bitlen = ctx->bitlen + 0x200;
      ctx->datalen = 0;
    }
  }
  return;
}
```

```c
void vzanrtdpzfwrd(SHA256_CTX *ctx,BYTE *hash)

{
  char cVar1;
  WORD i;
  
  i = ctx->datalen;
  if (ctx->datalen < 0x38) {
    ctx->data[i] = 0x80;
    while (i = i + 1, i < 0x38) {
      ctx->data[i] = '\0';
    }
  }
  else {
    ctx->data[i] = 0x80;
    while (i = i + 1, i < 0x40) {
      ctx->data[i] = '\0';
    }
    dfbrevgdvcrca(ctx,ctx->data);
    memset(ctx,0,0x38);
  }
  ctx->bitlen = ctx->bitlen + (ulong)(ctx->datalen << 3);
  ctx->data[0x3f] = (BYTE)ctx->bitlen;
  ctx->data[0x3e] = (BYTE)(ctx->bitlen >> 8);
  ctx->data[0x3d] = (BYTE)(ctx->bitlen >> 0x10);
  ctx->data[0x3c] = (BYTE)(ctx->bitlen >> 0x18);
  ctx->data[0x3b] = (BYTE)(ctx->bitlen >> 0x20);
  ctx->data[0x3a] = (BYTE)(ctx->bitlen >> 0x28);
  ctx->data[0x39] = (BYTE)(ctx->bitlen >> 0x30);
  ctx->data[0x38] = (BYTE)(ctx->bitlen >> 0x38);
  dfbrevgdvcrca(ctx,ctx->data);
  for (i = 0; i < 4; i = i + 1) {
    cVar1 = (char)i;
    hash[i] = (BYTE)(ctx->state[0] >> (('\x03' - cVar1) * '\b' & 0x1fU));
    hash[i + 4] = (BYTE)(ctx->state[1] >> (('\x03' - cVar1) * '\b' & 0x1fU));
    hash[i + 8] = (BYTE)(ctx->state[2] >> (('\x03' - cVar1) * '\b' & 0x1fU));
    hash[i + 0xc] = (BYTE)(ctx->state[3] >> (('\x03' - cVar1) * '\b' & 0x1fU));
    hash[i + 0x10] = (BYTE)(ctx->state[4] >> (('\x03' - cVar1) * '\b' & 0x1fU));
    hash[i + 0x14] = (BYTE)(ctx->state[5] >> (('\x03' - cVar1) * '\b' & 0x1fU));
    hash[i + 0x18] = (BYTE)(ctx->state[6] >> (('\x03' - cVar1) * '\b' & 0x1fU));
    hash[i + 0x1c] = (BYTE)(ctx->state[7] >> (('\x03' - cVar1) * '\b' & 0x1fU));
  }
  return;
}
```

It appears as though some initial state is being set, bitlength is being calculated, and then a series of bitwise shift
operations are occurring. These look like they may be related to key generation. To help determine if we've located
the key generation algorithm, let's set a breakpoint just before calling `fpToK`, and another just before encrypting our
first message. If we're right, we should be able to spot our key that was generated in use for encryption.

```bash
gef➤  br *(ywiuyvacoaplj+326)
Breakpoint 1 at 0x5555555ae6ea: file ggComms.cpp, line 401.
gef➤  br *(rhzahjabrnntl+169)
Breakpoint 2 at 0x5555555ae44f: file ggComms.cpp, line 366.
gef➤  c
```

After continuing once, we break just before calling the key generation algorithm. We expect the result to fill the first
argument, so take note of the address being passed in `RDI` so we can inspect the results after we step over the call.
Of note, we can see what appear to be a username, version, and timestamp being passed in as the other three arguments.

```bash
gef➤  ni
gef➤  telescope 0x00007fffffffe8e0 1
0x00007fffffffe8e0│+0x0000: 0x00007ffff77fdcd0  →  0xa619e8f7f3cd2376    ← $rax
gef➤  x/32bx 0x00007ffff77fdcd0
0x7ffff77fdcd0: 0x76    0x23    0xcd    0xf3    0xf7    0xe8    0x19    0xa6
0x7ffff77fdcd8: 0x2d    0xb6    0x9c    0xdc    0xf2    0xdd    0x35    0x1e
0x7ffff77fdce0: 0x81    0xb4    0xa2    0x9b    0x3a    0xc9    0x85    0xf8
0x7ffff77fdce8: 0x26    0xd4    0xb0    0x30    0x86    0xee    0x67    0xaa
```

We can see in our output our potential key which is `32` bytes. Let's continue execution to the encryption call to see
if we're right:

```bash
gef➤  c
_Z37crypto_secretbox_xsalsa20poly1305_refRKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES6_S6_ (
   $rdi = 0x00007fffffffe730 → 0x0000000000000002,
   $rsi = 0x00007fffffffe6f0 → 0x00007ffff77fcd40 → 0x0200006e2acb5d11,
   $rdx = 0x00007fffffffe710 → 0x00007ffff77fe5b0 → 0xb91e721db716cc0c,
   $rcx = 0x00007fffffffe900 → 0x00007ffff77fddf0 → 0xa619e8f7f3cd2376,
   $r8 = 0x00007ffff77fe5a8 → 0x002e770000000000
)
gef➤  x/32bx 0x00007ffff77fddf0
0x7ffff77fddf0: 0x76    0x23    0xcd    0xf3    0xf7    0xe8    0x19    0xa6
0x7ffff77fddf8: 0x2d    0xb6    0x9c    0xdc    0xf2    0xdd    0x35    0x1e
0x7ffff77fde00: 0x81    0xb4    0xa2    0x9b    0x3a    0xc9    0x85    0xf8
0x7ffff77fde08: 0x26    0xd4    0xb0    0x30    0x86    0xee    0x67    0xaa
```

As we prepare to call the `crypto_secretbox` function, we see that `RCX` contains our fourth argument that we suspected
was our key. Examining the contents reveals the same bytes we previously generated. We have found our key generation
algorithm.

To recap on what the algorithm is doing, it seems to be building a bytestream of 64 bytes that takes the following
format:

```
[username]+[short_version]+[timestamp]\x80[\x00...][bitlength]
```

Then altering the initial state that is established by shifting the values based on the byte stream.

## Preparing the pcap data

We now know the encryption algorithm being utilized (`xsalsa20`) and how the encryption key is being generated. We can
write a script to help parse our pcap data into a format that will be easy to process:

```python
#!/usr/bin/python3
import sys
import dpkt


def hex_string(b):
    return ''.join('' + "%02x" % letter for letter in b)


if __name__ == '__main__':
    with open("dib_data", "w") as file:
        for ts, pkt in dpkt.pcap.Reader(open(sys.argv[1], "rb")):
            eth = dpkt.ethernet.Ethernet(pkt)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
            if ip.data.dport == 6666:
                if ip.data.data:
                    file.write(f"{hex_string(ip.data.data)},{int(ts)}\n")
    with open("lp_data", "w") as file:
        for ts, pkt in dpkt.pcap.Reader(open(sys.argv[1], "rb")):
            eth = dpkt.ethernet.Ethernet(pkt)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
            if ip.data.sport == 6666:
                if ip.data.data:
                    file.write(f"{hex_string(ip.data.data)},{int(ts)}\n")
```

The above script will identify any network traffic inbound to, or outbound from port 6666, pull out the data bytes,
provide the timestamp, and record them to separate files for inbound/outbound traffic. This will enable us to focus on
decrypting one direction of the communications at a time.

Let's run our script on the pcap data from task 1:

```bash
python3 parsePcapData.py capture.pcap
```

## Cracking the pcap data

Thinking back on how the encryption key was being generated, we know that the key generation algorithm took in the
following variables:

```
username
short version
timestamp
```

Based on the length of those three elements, `bitlength` is also variable. The challenge prompt emphasized that the pcap
data contained traffic from other malware variants, and that we would be recovering UUIDs from clients associated with
the DIB. This implies two things:

1. Version numbers may not be the same as what we've recovered in our malware sample
2. Usernames may not necessarily follow the same format as the ones we've seen thus far since they are coming from
   different companies

Our approach will be to brute force keys while varying the above inputs. For version, observing the the short version
used in our version of the malware is `3.3.3.3` we can try all combinations of `X.X.X.X` where `X` represents a single
digit. For usernames, we can leverage existing username dumps - one such repository is listed in the codebreaker
references page: [SecLists](https://github.com/danielmiessler/SecLists), and specifically, we will first focus
on [top-usernames-shortlist.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt)
to see if we can get some easy wins. For timestamp, we can include a range that is `+-5` from the timestamp given in the
pcap.

For each key we generate, we will attempt to decrypt each message. To do so, we will need the help of a library that can
decrypt `xsalsa20` encrypted messages. After some experimentation, I opted to create my program in `C++` and utilize
the [libsodium](https://doc.libsodium.org/) library. Once libsodium is installed, we can leverage it by linking it at
compile time with:

```
g++ cracker.cpp -lsodium -o cracker
```

After a significant amount of experimentation, I developed a fairly robust program that takes in files containing a user
list, version list, and the parsed pcap data to process, and brute forces keys as discussed above. The full program
source can be found [here](cracker.cpp).

NOTE: This program is far from perfect, and is fairly messy in several areas to
include some vulnerabilities, but it does what we need it to for this challenge.

```bash
$ ./cracker top-usernames-shortlist.txt all_versions dib_data
Message: f2 a0 38 0e fa f5 5d 37 22 f0 b6 70 e1 f5 65 1d - 82 76 9b 1f 55 59 54 ae 11 ad a5 25 1c ae - 05 e7 0e 38 99 ce 36 cf 9d c4 b4 f5 23 02 29 af - 9a eb 1b 10
                Clutter                                         FrontMagic                                      UUID                            EndMagic
Username: root
Time: 1615898797
Version: +3.3.3.3+
Key: 2adb7941bd403df5718a7008c021b316841d75c9e8f9559d7933642108b5273c
Decrypted: 11 5d cb 2a 6e 00 00 02 00 02 6e 08 00 10 - 6ec9e6ed-25e0-4172-8f0a-b9b1340780e6 - ee 37 e6 14
OTHER - 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
RAW:
]�*nn���%�Ar�
��4���7�

Message: 45 c0 57 e5 78 db c2 8d b8 a2 59 72 82 5b 51 25 - f0 02 3f 71 f3 d1 c5 da 66 8b 96 7b d6 3f - c1 5b c6 90 b4 b6 51 ff 8c a9 aa 0b 9f 65 ab 72 - cd d8 7c 57
                Clutter                                         FrontMagic                                      UUID                            EndMagic
Username: root
Time: 1615898797
Version: +3.3.3.3+
Key: 2adb7941bd403df5718a7008c021b316841d75c9e8f9559d7933642108b5273c
Decrypted: 11 5d cb 2a 6e 00 00 02 00 06 6e 08 00 10 - 6ec9e6ed-25e0-4172-8f0a-b9b1340780e6 - 6e 14 00 08
OTHER - 736f7572636573006e1c0006656d707479006e2000006e24000100ee37e6140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
RAW:
]�*nn���%�Ar�
��4��nsourcesnemptyn n$�7�
```

For reference, the format of the `all_versions` file is:

```
+0.0.0.0+
+0.0.0.1+
+0.0.0.2+
...
+9.9.9.9+
```

Running our program against the top usernames list gives us two cracked messages from one session. As we proceed, we'll need to think
carefully about our search space and identify areas where we can be more restrictive and areas where we need to be less
restrictive.

Let's expand our username list - we can
use [names.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt) from the
SecLists repo which contains just over 10000 usernames. Looking back at the pcap data, we can see that each client
session consists of several messages. We really only need one message for each session, and specifically the init
message. If we go back and examine the binary, we'll see that `78` bytes ends up getting sent to the LP for the init
message. We also know we're only looking for communications from DIB clients. Let's further restrict our [pcap parsing
script](parsePcapData.py) to only pull DIB messages that are `78` bytes. This will cut out some of the noise that we don't care about.

After running our cracker, we get another three sessions in about 90 minutes:

```bash
Message: 3a fa ce 8c 19 95 6d d4 3f b9 69 c4 97 7f 8e 62 - b8 d7 4e 13 a5 87 96 97 55 e7 21 14 3c 92 - c0 02 4e 6b 75 b6 6b 60 71 eb ce ea b9 a2 d7 a1 - 28 a3 8c db
                Clutter                                         FrontMagic                                      UUID                            EndMagic
Username: bernadina
Time: 1615898794
Version: +2.1.7.5+
Key: 5ab254967277975c5c554291dd4460dc1eed78210c2238fdf95869f2694e0363
Decrypted: 11 5d cb 2a 6e 00 00 02 00 02 6e 08 00 10 - 42037ebd-a655-481f-956e-4e4c2bd99d17 - ee 37 e6 14
OTHER - 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
RAW:
]�*nB~��UH�nNL+ٝ�7�

Message: cf 74 3c a9 40 64 21 e2 0e 4d 22 e0 0c 9d c3 4c - 25 34 2b 7d 5a 18 fc ff c3 20 7e cc bf 5d - e5 c1 f6 19 f0 e4 72 cd 68 12 22 d8 71 e2 62 3d - 28 b5 b6 f6
                Clutter                                         FrontMagic                                      UUID                            EndMagic
Username: quincy
Time: 1615898810
Version: +2.0.7.0+
Key: 5e98a782a3734efe52919e769fe5bf93baf728d9f73874b4150a49d1869cf5a3
Decrypted: 11 5d cb 2a 6e 00 00 02 00 02 6e 08 00 10 - b48efb2a-063b-43cd-9bfe-db06d7ef92a4 - ee 37 e6 14
OTHER - 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
RAW:
]�*n���*;C͛����7�

Message: f7 30 2f 12 17 d2 14 b5 0e 9b 7a de 9f 16 c7 0d - 41 10 1e db 42 b7 c2 fa e3 08 27 9e b9 3c - a7 fe fa ff 25 0e 27 0b 4f 68 10 75 4b f7 7d 02 - a7 85 2f 0c
                Clutter                                         FrontMagic                                      UUID                            EndMagic
Username: snehal
Time: 1615898855
Version: +1.1.6.9+
Key: d45c0e750c5d9de44c1c9f154dd5ae602644dbe32b8bc92c1818e4d834faddeb
Decrypted: 11 5d cb 2a 6e 00 00 02 00 02 6e 08 00 10 - 1670edb3-7964-4aad-88ef-9be0b91611f5 - ee 37 e6 14
OTHER - 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
RAW:
]�*np�ydJ������7�
```

Noting that our first cracked session was not from a DIB ip, we can submit the above three recovered UUIDs to solve task 8.