loxvm: loxvm.c
	cc -Wall -Wextra -Wpedantic -O3 loxvm.c -o loxvm

format: loxvm.c
	clang-format -i --style=Google loxvm.c

.PHONY: clean
clean:
	rm -rf loxvm
