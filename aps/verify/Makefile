# The path to the wolfssl directory must be set correctly for your environment.
WOLFROOT = ../wolfssl

CC= gcc
CFLAGS = $(EX_CFLAGS) -DWOLFSSL_USER_SETTINGS -I. -I$(WOLFROOT) -Os
ASFLAGS=-DWOLFSSL_USER_SETTINGS -I. -I$(WOLFROOT)

OBJ = \
	$(WOLFROOT)/wolfcrypt/src/rsa.o\
	$(WOLFROOT)/wolfcrypt/src/sha256.o\
	$(WOLFROOT)/wolfcrypt/src/hash.o\
	$(WOLFROOT)/wolfcrypt/src/asn.o\
	$(WOLFROOT)/wolfcrypt/src/wolfmath.o\
	$(WOLFROOT)/wolfcrypt/src/memory.o\
	$(WOLFROOT)/wolfcrypt/src/sp_int.o\
	$(WOLFROOT)/wolfcrypt/src/sp_c32.o\
	$(WOLFROOT)/wolfcrypt/src/random.o\
	$(WOLFROOT)/wolfcrypt/src/misc.o\
	
.PHONY: all clean size mem

all: verify

RSA_PSSverify.o: RSA_PSSverify.c
	$(CC) $(CFLAGS) -c RSA_PSSverify.c

verify: clean $(OBJ) RSA_PSSverify.o
	$(CC) $(CFLAGS) -o verify RSA_PSSverify.o $(OBJ)
clean:
	rm -f verify $(WOLFROOT)/wolfcrypt/src/*.o ./*.o
size :
	size $(OBJ) RSA_PSSverify.o verify
