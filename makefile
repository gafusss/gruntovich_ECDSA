runtest:
	cd out && ./main

test: all
	cd out && ./main

all: gen a b main

main: gen a b dir
	gcc main.c -Wall -o out/main

a: dir
	gcc a.c -Wall -o out/a -lcrypto -lrhash

b: dir
	gcc b.c -Wall -o out/b -lcrypto -lrhash

gen: dir
	gcc gen.c -Wall -o out/gen -lcrypto

dir:
	-mkdir out

clean:
	-rm -r out
