all: mock-test remote-test lib


mock-test: src/gem.c src/parse-schema.c test/mock-test.c
	$(CC) -std=gnu99 -o mock-test src/gem.c src/parse-schema.c test/mock-test.c -lrtosc -luv -g -O0

remote-test: src/gem.c src/parse-schema.c test/basic-remote.c
	$(CC) -std=gnu99 -o remote-test src/gem.c src/parse-schema.c test/basic-remote.c -lrtosc -luv -g -O0

lib: src/gem.c src/parse-schema.c
	$(CC) -std=gnu99 -O0 -g -fPIC -c src/gem.c src/parse-schema.c
	$(AR) rcs libosc-bridge.a gem.o parse-schema.o
