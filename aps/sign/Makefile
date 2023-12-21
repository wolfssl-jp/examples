# The path to the wolfssl directory must be set correctly for your environment.
WOLFROOT = ../wolfssl

CC= gcc
CFLAGS = $(EX_CFLAGS) -DWOLFSSL_USER_SETTINGS -I. -I$(WOLFROOT) -Os -g
ASFLAGS=-DWOLFSSL_USER_SETTINGS -I. -I$(WOLFROOT)

OBJ = \
	$(WOLFROOT)/wolfcrypt/src/rsa.o\
	$(WOLFROOT)/wolfcrypt/src/sha256.o\
	$(WOLFROOT)/wolfcrypt/src/hash.o\
	$(WOLFROOT)/wolfcrypt/src/asn.o\
	$(WOLFROOT)/wolfcrypt/src/coding.o\
	$(WOLFROOT)/wolfcrypt/src/wolfmath.o\
	$(WOLFROOT)/wolfcrypt/src/memory.o\
	$(WOLFROOT)/wolfcrypt/src/sp_int.o\
	$(WOLFROOT)/wolfcrypt/src/sp_c32.o\
	$(WOLFROOT)/wolfcrypt/src/random.o\
	$(WOLFROOT)/wolfcrypt/src/misc.o\
	$(WOLFROOT)/wolfcrypt/src/wc_port.o\
	
.PHONY: all clean size mem

all: sign keygen

RSA_PSSsign.o: RSA_PSSsign.c
	$(CC) $(CFLAGS) -c RSA_PSSsign.c

sign:   clean $(OBJ) RSA_PSSsign.o
	$(CC) $(CFLAGS) -o sign RSA_PSSsign.o $(OBJ)

RSAkeygen.o: RSAkeygen.c
	$(CC) $(CFLAGS) -c RSAkeygen.c

keygen:   clean $(OBJ) RSAkeygen.o
	$(CC) $(CFLAGS) -o keygen RSAkeygen.o $(OBJ)

clean:
	rm -f verify $(WOLFROOT)/wolfcrypt/src/*.o ./*.o
size :
	size $(OBJ) RSA_PSSsign.o sign
