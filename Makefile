OBJS= \
	aeskeys_amd64.o \
	tomcrypt_aesni.o

CFLAGS+= \
	-O3 \
	-g \
	-I ../libtomcrypt/src/headers \
	-L ../libtomcrypt \
	-L ../tomsfastmath \
	-DTFM_DESC \
	-DUSE_TFM \
	-march=native

test: $(OBJS) test.o
	$(CC) $(CFLAGS) -o $@ $^ -ltomcrypt -ltfm

libtomcrypt_aesni.a: $(OBJS)
	ar -rc libtomcrypt_aesni.a $(OBJS)

.PHONY: clean
clean:
	-rm libtomcrypt_aesni.a *.o
