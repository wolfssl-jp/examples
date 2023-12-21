#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include <errno.h>

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>

int main(int argc, char **argv)
{
    WC_RNG rng;
    RsaKey rsaKey;
#define PRI_SIZE 1200
#define PUB_SIZE 300
    uint8_t pri[PRI_SIZE], pub[PUB_SIZE];
    int  priSz, pubSz;
    FILE *fpri, *fpub;


    if(wc_InitRng(&rng) != 0) {
        fprintf(stderr, "Error on initializing RNG\n");
        exit(1);
    }
    if(wc_InitRsaKey(&rsaKey, NULL) != 0) {
        fprintf(stderr, "Unable to initialize RSA key\n");
        exit(1);
    }
    
    if (wc_MakeRsaKey(&rsaKey, 2048, WC_RSA_EXPONENT, &rng) != 0) {
        fprintf(stderr, "Unable to generate RSA key\n");
        exit(1);
    }
    if ((priSz = wc_RsaKeyToDer(&rsaKey, pri, PRI_SIZE)) < 0){
        fprintf(stderr, "Unable to export private key(%d)\n", priSz);
        exit(2);
    }
    printf("Exporting private key(%d)\n", priSz);
    fpri = fopen(argv[1], "wb");
    if (fpri == NULL) {
        fprintf(stderr, "Unable to open file '%s'\n", argv[1]);
        exit(3);
    }
    fwrite(pri, priSz, 1, fpri);
    fclose(fpri);

    if ((pubSz= wc_RsaKeyToPublicDer(&rsaKey, pub, PUB_SIZE)) < 0) {
        fprintf(stderr, "Unable to export public key(%d)\n", pubSz);
        exit(2);
    }
    printf("Exporting public key(%d)\n", pubSz);
    fpub = fopen(argv[2], "wb");
    if (fpub == NULL) {
        fprintf(stderr, "Unable to open file '%s'\n", argv[2]);
        exit(4);
    }
    fwrite(pub, pubSz, 1, fpub);
    fclose(fpub);

    wc_FreeRng(&rng);
}
