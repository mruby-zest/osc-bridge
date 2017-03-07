SRC = src/bridge.c src/cache.c src/parse-schema.c src/schema.c
CFLAGS_ = -std=gnu99 -Wall -Wextra

all: mock-test remote-test lib


mock-test: $(SRC) test/mock-test.c
	$(CC) $(CFLAGS_) -o mock-test $(SRC) test/mock-test.c -lrtosc -luv -g -O0

remote-test: $(SRC) test/basic-remote.c
	$(CC) $(CFLAGS_) -o remote-test $(SRC) test/basic-remote.c -lrtosc -luv -g -O0

lib: $(SRC)
	$(CC) $(CFLAGS) $(CFLAGS_) -O3 -g -fPIC -c $(SRC) -I../../deps/rtosc/include -I../../deps/libuv-v1.9.1/include/
	$(AR) rcs libosc-bridge.a gem.o parse-schema.o
