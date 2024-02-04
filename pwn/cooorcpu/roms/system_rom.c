int main(void) __attribute__ ((section ("entry")));

void set_priv2() {
	asm volatile ("add x2, x10, 0");
	asm volatile (".byte 0b00110100, 0, 2, 0");
}

void set_priv(int *cpl) {
	asm volatile ("lb x10, 0(x10)");
	asm volatile (".byte 0b00110100, 0, 0b101, 0");
	asm volatile (".byte 0b01110010, 0, 0, 0");
}

int main() {
	asm volatile ("addi x10, x0, 1");
	asm volatile (".byte 0b00110100, 0, 0b101, 0");

	for (int i = 0; i < 10; i++);
	asm volatile (".byte 0b1110001, 0, 0, 0");

	int n = 0;
	set_priv(&n);
}

