all: mock-test remote-test lib


mock-test: src/gem.c src/parse-schema.c test/mock-test.c
	clang -std=gnu99 -o mock-test src/gem.c src/parse-schema.c test/mock-test.c -lrtosc -luv -g -O0

remote-test: src/gem.c src/parse-schema.c test/basic-remote.c
	clang -std=gnu99 -o remote-test src/gem.c src/parse-schema.c test/basic-remote.c -lrtosc -luv -g -O0

lib: src/gem.c src/parse-schema.c
	clang -std=gnu99 -fPIC -c src/gem.c src/parse-schema.c
	ar rcs libosc-bridge.a gem.o parse-schema.o
