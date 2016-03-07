mock-test: src/gem.c src/parse-schema.c test/mock-test.c
	clang -std=gnu99 -o mock-test src/gem.c src/parse-schema.c test/mock-test.c -lrtosc
