
test: all
	cd out && ./main

all: gen a b main

main: gen a b dir
	gcc -Wall -o out/main main.c

a: dir
	gcc -Wall -lcrypto -lrhash -o out/a a.c

b: dir
	gcc -Wall -lcrypto -lrhash -o out/b b.c

gen: dir
	gcc -Wall -lcrypto -o out/gen gen.c

dir:
	-mkdir out

clean:
	-rm -r out