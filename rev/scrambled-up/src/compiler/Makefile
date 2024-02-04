.PHONY: get_debug_modules

target/release/rev-compiler: src/main.rs src/compile.rs src/parse.rs src/obfuscate.rs
	cargo build --release

get_debug_modules:
	rm -rf modules
	mkdir modules
	sftp root@159.65.186.237 <<< "get /root/rev-project/cmake-build-debug/*.text modules"

compile:
	target/release/rev-compiler

graph.dot graph.obf.dot graph.c: target/release/rev-compiler get_debug_modules compile
	:

run: graph.c
	cp graph.c ../harness/src/gen.c
	dot -Tsvg -Ksfdp graph.dot > output.svg
	dot -Tsvg -Ksfdp -x graph.obf.dot > output.obf.svg
