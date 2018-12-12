OBJS= \
	aeskeys_amd64.o \
	tomcrypt_aesni.o

CFLAGS+= \
	-O3 \
	-g \
	-I libtomcrypt/src/headers \
	-I libtommath \
	-DLTM_DESC \
	-DUSE_LTM \
	-march=native

libtomcrypt_aesni.a: $(OBJS)
	ar -rc libtomcrypt_aesni.a $(OBJS)

.PHONY: clean
clean:
	-rm libtomcrypt_aesni.a *.o
