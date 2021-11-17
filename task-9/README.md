# Task 9

For task 9, we are given access to the LP, however the challenge prompt warns us that we'll only have about three hours to interact with it before we lose access, and that there is a cooling off period between spin-ups, so we'll need to be deliberate with our access.   Our task is to identify other client UUIDs that have registered with the LP.

## Understanding the LP communications protocol 

If you recall in the task 8 prompt, it mentioned that the commands we reverse engineered in the malicious copy of `make` we recovered likely only contained a subset of the communications protocol supported by the LP.  Let's use the `cracker` program we developed in [task 8](../task-8/) to decrypt some more messages to see if we can identify more of the protocol.

We have already uncovered a handful of usernames associated with these messages, so let's front load those usernames in our username list.  We also want to expand our messages to include all messages to and from the LP.  We can start with just the DIB communications, and expand it to other messages as well if we don't get everything we need.  Running our cracker against all the DIB messages with our known usernames gives us some quick results, and we see some interesting messages immediately:

```
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

Message: 84 ec 02 19 1c 44 83 83 b5 3f ab f5 7d 38 67 a6 - b2 78 24 0e 4e ea 8e 47 a6 25 86 32 ed f7 - aa fd df 66 cf 52 0f 98 58 1b 8b 71 dc b1 5b 2e - f8 69 a4 ab
                Clutter                                         FrontMagic                                      UUID                            EndMagic
Username: snehal
Time: 1615898855
Version: +1.1.6.9+
Key: d45c0e750c5d9de44c1c9f154dd5ae602644dbe32b8bc92c1818e4d834faddeb
Decrypted: 11 5d cb 2a 6e 00 00 02 00 03 6e 08 00 10 - 1670edb3-7964-4aad-88ef-9be0b91611f5 - ee 37 e6 14
OTHER - 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
RAW:
]�*np�ydJ������7�

Message: 9f 27 c1 1b 94 02 ec d1 13 2a c7 c3 fc a9 5c a7 - 62 4f f2 4b a6 38 7c b4 2a 40 45 f4 16 b4 - 31 45 6d 2f 1a 46 b6 3d 2a 7d a7 8f 9a 19 1d 37 - 6e cc 81 5f
                Clutter                                         FrontMagic                                      UUID                            EndMagic
Username: snehal
Time: 1615898855
Version: +1.1.6.9+
Key: d45c0e750c5d9de44c1c9f154dd5ae602644dbe32b8bc92c1818e4d834faddeb
Decrypted: 11 5d cb 2a 6e 00 00 02 00 04 6e 08 00 10 - 1670edb3-7964-4aad-88ef-9be0b91611f5 - 6e 14 00 3c
OTHER - 2f746d702f656e64706f696e74732f31363730656462332d373936342d346161642d383865662d3962653062393136313166352f7461736b696e6700ee37e6140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
RAW:
]�*np�ydJ�����n</tmp/endpoints/1670edb3-7964-4aad-88ef-9be0b91611f5/tasking�7�

Message: b4 f5 df a3 55 f6 3a a8 7b bf da 23 d0 16 43 25 - 16 af 7d 34 49 32 2c 28 6d 6a e1 cc 66 54 - 65 a9 96 18 3f 39 36 4b 47 4e c9 4a 41 57 8d d5 - f6 0e 55 67
                Clutter                                         FrontMagic                                      UUID                            EndMagic
Username: snehal
Time: 1615898855
Version: +1.1.6.9+
Key: d45c0e750c5d9de44c1c9f154dd5ae602644dbe32b8bc92c1818e4d834faddeb
Decrypted: 11 5d cb 2a 6e 00 00 02 00 05 6e 08 00 10 - 1670edb3-7964-4aad-88ef-9be0b91611f5 - 6e 14 00 3c
OTHER - 2f746d702f656e64706f696e74732f31363730656462332d373936342d346161642d383865662d3962653062393136313166352f7461736b696e67006e1c00077461736b2d3200ee37e6140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
RAW:
]�*np�ydJ�����n</tmp/endpoints/1670edb3-7964-4aad-88ef-9be0b91611f5/taskingntask-2�7�
...
```

Looking at the decrypted bytes, we see a similar format from what we previously reverse engineered:


```
[MAGIC_START][PARAM_CMD][CMD_LENGTH][CMD_XXX][PARAM_UUID][UUID_LENGTH][UUID]...
```

For a handful of messages, instead of `[MAGIC_END]` after `[UUID]`, we see some other bytes instead.  Let's look close at `CMD_XXX`.  We knew previously that `CMD_INIT` was `0002`, and we see that for the first message in this sessions.  For subsequent messages, however, we see the values `0003`, `0004`, and `0005`, which indicate that the client is sending commands other than init.  In our version of the malware, we do not see these commands hard coded, so we'll need to take some educated guesses at their meaning.

We can use the response messages from the LP to help decipher this functionality:

```
Message: 3f de 9a a6 83 2b 34 19 29 10 28 0e c4 52 1c 7b - 08 1a 32 5c cb 75 8f 4a 8c ee b6 44 22 5a - 6b 8f 6a ce 4b 4d 0e 4f 7a 1d df b1 dc fc 87 f1 - e1 30 11 96
                Clutter                                         FrontMagic                                      UUID                            EndMagic
Username: snehal
Time: 1615898855
Version: +1.1.6.9+
Key: d45c0e750c5d9de44c1c9f154dd5ae602644dbe32b8bc92c1818e4d834faddeb
Decrypted: 11 5d cb 2a 6e 28 00 04 00 00 00 00 ee 37 - e6140000-0000-0000-0000-000000000000 - 00 00 00 00
OTHER - 0000000000000000000000000000000000000000000000000000
RAW:
]�*n(�7�

Message: 42 cf 93 da df 50 7f 66 51 e4 76 67 ad 44 ce 6e - 63 c0 cc 7b e1 6d 77 e6 60 c4 ba 44 96 eb - a2 37 8a 9f 61 30 fe fc 9a 76 9d b7 87 d3 5e 52 - f9 cb 4e b6
                Clutter                                         FrontMagic                                      UUID                            EndMagic
Username: snehal
Time: 1615898855
Version: +1.1.6.9+
Key: d45c0e750c5d9de44c1c9f154dd5ae602644dbe32b8bc92c1818e4d834faddeb
Decrypted: 11 5d cb 2a 6e 14 00 3c 2f 74 6d 70 2f 65 - 6e64706f-696e-7473-2f31-363730656462 - 33 2d 37 39
OTHER - 36342d346161642d383865662d3962653062393136313166352f7461736b696e6700ee37e6140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
RAW:
]�*n</tmp/endpoints/1670edb3-7964-4aad-88ef-9be0b91611f5/tasking�7�

Message: f9 0e e9 7b 31 ce da ec 9b 7e 60 a6 13 37 dc 3f - 7c e1 33 61 fc 55 bf cb b0 6c 1d 15 fd 19 - 60 d8 a7 a1 a3 8a 2b 49 4f 57 77 da 88 7c d7 81 - f9 cb 4e b6
                Clutter                                         FrontMagic                                      UUID                            EndMagic
Username: snehal
Time: 1615898855
Version: +1.1.6.9+
Key: d45c0e750c5d9de44c1c9f154dd5ae602644dbe32b8bc92c1818e4d834faddeb
Decrypted: 11 5d cb 2a 6e 18 00 07 74 61 73 6b 2d 32 - 006e1800-0774-6173-6b2d-3100ee37e614 - 00 00 00 00
OTHER - 00000000000000000000000000000000000000000000000000000000000000000000000000000000
RAW:
]�*ntask-2ntask-1�7�

Message: 9e 83 c2 66 9f c2 e0 5b 48 3c 96 46 1b 8d 8f 8b - 23 1d f9 90 cb 9c 85 3d 62 1e 86 f5 64 a7 - 2e ec 0e 2c 43 98 40 f0 35 74 6e 2d 7d 50 a1 a8 - 70 1c 4e b6
                Clutter                                         FrontMagic                                      UUID                            EndMagic
Username: snehal
Time: 1615898855
Version: +1.1.6.9+
Key: d45c0e750c5d9de44c1c9f154dd5ae602644dbe32b8bc92c1818e4d834faddeb
Decrypted: 11 5d cb 2a 6e 20 00 14 52 55 4e 3a 20 63 - 6174202f-6574-632f-6973-7375650aee37 - e6 14 00 00
OTHER - 000000000000000000000000000000000000000000000000000000000000000000000000000000000000
RAW:
]�*n RUN: cat /etc/issue
�7�
...
```

In theory, these LP response messages should map to the client messages in order, so starting at the top, we can see what looks like a somewhat uninteresting init acknowledgement.  The next command sent from the client was `0003`.  Observing the response from the LP, we see that it sent the string `/tmp/endpoints/1670edb3-7964-4aad-88ef-9be0b91611f5/tasking`.  The client, then sent command `0004` with the string `/tmp/endpoints/1670edb3-7964-4aad-88ef-9be0b91611f5/tasking`, to which the LP responded with `task-2ntask-1`.  Finally, the client sends command `0005` with `/tmp/endpoints/1670edb3-7964-4aad-88ef-9be0b91611f5/taskingntask-2` and receieves `RUN: cat /etc/issue` as a response.

If we dig in a bit more, we can see some other familiar hard-coded magic bytes present in these latter communications.  Before directories and filenames, we see corresponding `PARAM_DIRNAME` and `PARAM_FILENAME` bytes, followed by what seems to be a two byte string length.  These magic bytes are:

| Name | Value
| ---- | ---- |
| PARAM_DIRNAME | 6e14 |
| PARAM_FILENAME | 6e1c |

Reasoning about the above back and forth communications, it seems as though the client is asking for a tasking directory with command `0003`, requesting a listing of the contents of a directory with command `0004`, and requesting to download the contents of a file with command `0005`.  We can use this knoweldge moving forward as we determine how to get more information from the LP.

## Communicating with the LP

Now that we have a better understanding of the LP's communications protocol, we can modify our [cracker](../task-8/cracker.cpp) program from task 8 to instead encrypt and send messages to the LP, and receive responses.  Remember, our task is to identify other UUIDs of clients that have communicated with the LP.  We know we have a command at our disposal that will list the contents of a directory, and we know that in one of our communications we observed the directory `/tmp/endpoints/1670edb3-7964-4aad-88ef-9be0b91611f5/tasking`.  It is likely that `/tmp/endpoints` contains additional UUIDs from client connections, so we will craft our messages to list the contents of this directory.

For this to work, we will need to mimic the behavior of a client, so we will need our program to do the following:

1. Send an initial crypt negotiation
2. Send encrypted messages that match the protocol we've reversed
3. Receive responses from the LP

If we successfully communicate with the LP, we should be able to capture the network traffic in wireshark and crack the responses with our cracker program.

### Initial Crypt Negotiation

Let's take another look at how the inital crypt negotiation occurs:

```c
int initialCryptNegotiation(int sock,string *fp)

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
  generateRandomBytes(&nonce,0x18);
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
  result = sendOverSocket(sock,vbuf,bufLen);
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

Similarly to how the message encryption function works, this function takes in some bytes to encrypt, encrypts them with a key (this time the public key we disocvered in [task 6](../task-6/)), and then sends the encrypted result with nonce and length header to the LP.  Let's take a look in gdb to see what we're passing into this function:

```bash
gef➤  br *(ywiuyvacoaplj+437)
gef➤  c

_Z13ztwacocfpsxpgiNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE (
   int var_0 = 0x0000000000000005,
   std::string var_1 = 0x00007fffffffe920 → 0x00007ffff77ef410 → "dXNlcm5hbWU9dW5rbm93bg==,dmVyc2lvbj0zLjMuMy4zLUlaV[...]"
)

gef➤  x/1s 0x00007ffff77ef410
0x7ffff77ef410: "dXNlcm5hbWU9dW5rbm93bg==,dmVyc2lvbj0zLjMuMy4zLUlaVA==,b3M9TGludXg=,dGltZXN0YW1wPTE2MzcwODM1MzA="
```

When we break right before calling our initial crypt function, we see that the second argument contains a pointer to the following string:

```
dXNlcm5hbWU9dW5rbm93bg==,dmVyc2lvbj0zLjMuMy4zLUlaVA==,b3M9TGludXg=,dGltZXN0YW1wPTE2MzcwODM1MzA=
```

This appears to be a series of base64 encoded strings that are comma delimited.  Decoding the strings gives the following:

```
username=unknown
version=3.3.3.3-IZT
os=Linux
timestamp=1637083530
```

The base64 string is encrypted as noted above, and sent along with a length header and nonce just like the other messages.  This initial crypt negotiation is providing the LP with the information it needs to decrypt the follow-on message traffic.

### Putting it all together

Now that we know how the initial crypt negotiation works, and how subsequent messages are encrypted and sent, we can mimic this communication flow in our modified cracker, which is now [lpcomms.cpp](lpcomms.cpp).  Through command line arguments, we will pass a plaintext list of handcrafted commands to send to the LP, along with a username, version, and os to craft the initial crypt message and encrypt follow-on messages with.

We can compile the program the same way we did for cracker:

```bash
g++ lpcomms.cpp -lsodium -o lpcomms
```

We will send two messages in addition to the initial crypt message:
1. A session init message
2. A request to list the contents of `/tmp/endpoints`

We can pre-craft these messages:

```
115dcb2a6e00000200026e0800101b8cbd03d5e64265b5155556e875c7ddee37e614
115dcb2a6e00000200046e0800101b8cbd03d5e64265b5155556e875c7dd6e14000e2f746d702f656e64706f696e747300ee37e614
```

Now we just need to spin up the infrastructure, ensure wireshark is capturing packets, and start communicating.

```
./lpcomms 54.174.219.103 list_endpoints root 3.3.3.3 Linux
```

Once we execute the above, we can see our traffic go out to the LP and the responses coming back in Wireshark.  When the exchange is complete, we can export the captured packets, parse them with our modified [parsePcapData.py](parsePcapData.py) script, and crack the responses from the LP with our cracker program from task 8 (I went ahead and added root as the first name in the username list):

```
./cracker names.txt all_versions lp_data
Message: 6d 42 9d 28 25 80 9c 28 e7 be 4f a6 dd e1 66 85 - 8f 7d bd 41 96 39 41 15 f0 0c db 03 6f 18 - 60 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 - 00 00 00 00
                Clutter                                         FrontMagic                                      UUID                            EndMagic
Username: root
Time: 1637111186
Version: +3.3.3.3+
Key: 05a4246dd0b827dbe3821975375d2c84efe0ec30e4ad991c2eef2ecc2200db59
Decrypted: 11 5d cb 2a 6e 28 00 04 00 00 00 00 ee 37 - e6140000-0000-0000-0000-000000000000 - 00 00 00 00
OTHER - 0000000000000000000000000000000000000000000000000000
RAW:
]�*n(�7�

Message: 91 6c 1d e0 f5 94 1f 74 20 2a bf a0 a5 f3 6d da - 2f 47 bf 68 11 08 f8 9d 91 61 9a 7f 49 48 - 6d e2 77 fa f2 8f f0 a5 d5 e4 e5 ac a0 5b d4 fa - f9 b2 67 9c
                Clutter                                         FrontMagic                                      UUID                            EndMagic
Username: root
Time: 1637111186
Version: +3.3.3.3+
Key: 05a4246dd0b827dbe3821975375d2c84efe0ec30e4ad991c2eef2ecc2200db59
Decrypted: 11 5d cb 2a 6e 18 00 25 33 31 64 33 34 31 - 30612d33-6534-382d-3662-39362d366334 - 64 2d 62 35
OTHER - 33613637333165386237006e18002562656463343834612d363564302d346537372d626466312d616133396563623566373963006e18002534306633633231642d633166652d343734322d396266312d613535633433663863356639006e18002537353831383735382d626464652d343062622d396235632d383634343039373933613864006e18002530356533646431322d383666342d343030342d623335302d356561633635363465656464006e18002535393364613865642d316539352d343235662d623463312d34663830333233646334656600ee37e6140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
RAW:
]�*n%31d3410a-3e48-6b96-6c4d-b53a6731e8b7n%bedc484a-65d0-4e77-bdf1-aa39ecb5f79cn%40f3c21d-c1fe-4742-9bf1-a55c43f8c5f9n%75818758-bdde-40bb-9b5c-864409793a8dn%05e3dd12-86f4-4004-b350-5eac6564eeddn%593da8ed-1e95-425f-b4c1-4f80323dc4ef�7�
```

We see the response to our init message, followed by a response to our request for directory listing, and as we expected, we see a series of UUIDs returned to us.  Noting that the UUID that was generated for our own exfil attempt is the first one in the list, we can submit all other UUIDs for a correct solution to task 9:

```
bedc484a-65d0-4e77-bdf1-aa39ecb5f79c
40f3c21d-c1fe-4742-9bf1-a55c43f8c5f9
75818758-bdde-40bb-9b5c-864409793a8d
05e3dd12-86f4-4004-b350-5eac6564eedd
593da8ed-1e95-425f-b4c1-4f80323dc4ef
```