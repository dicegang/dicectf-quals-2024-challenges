int main(void) __attribute__ ((section ("entry")));

typedef void call(void);

int main() {
//	int i = 0;
//	i += 1;
	asm volatile ("addi x2, x0, 1");
//        asm volatile (".byte 0b0110100, 0, 1, 0");

	register call* ptr = (call*) 0x4070;
	asm volatile ("addi x4, x0, 1");
	asm volatile("ecall");
	ptr();
	asm volatile (".byte 0b1110000, 0, 0, 0");

	while (1) {}
}
