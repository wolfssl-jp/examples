
#include <stdio.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>

static void dump_bytes(const byte *p, word32 len)
{
    printf("\n");
    for (; len; len--, p++) {
        if (((unsigned long)p & 0x07) == 0)
        {
            printf("\n");
        }
        printf("%02x ", *p);
    }
    printf("\n");
}

int sign(byte *msg, int msg_size,
           byte *sig, word32 sig_size,
           byte *pri, int pri_size)
{
    wc_Sha256 sha256;
    byte msgd[WC_SHA256_DIGEST_SIZE];
    byte *msg_p;

    RsaKey rsaKey;
    word32 idx = 0;

    WC_RNG rng;

    int ret;


    #define MSG_BLOCK 64

    /* Message Hash */
    ret = wc_InitSha256(&sha256);
    if (ret < 0) {
        printf("Error wc_InitSha256(%d): \n", ret);
        return -1;
    }

    for (msg_p = msg; msg_size >= MSG_BLOCK;
         msg_size -= MSG_BLOCK, msg_p += MSG_BLOCK) {
        ret = wc_Sha256Update(&sha256, msg_p, MSG_BLOCK);
        if (ret < 0)
        {
            printf("Error wc_Sha256Update(%d): \n", ret);
            return -1;
        }
    }
    if (msg_size > 0) {
        ret = wc_Sha256Update(&sha256, msg_p, MSG_BLOCK);
        if (ret < 0) {
            printf("Error wc_Sha256Update(%d): \n", ret);
            return -1;
        }
    }

    ret = wc_Sha256Final(&sha256, msgd);
    if (ret < 0) {
        printf("Error wc_Sha256Final(%d): \n", ret);
        return -1;
    }

    printf("\nHash");
    dump_bytes(msgd, WC_SHA256_DIGEST_SIZE);

    /* Set up private key */
    ret = wc_InitRsaKey(&rsaKey, NULL);
    if (ret < 0) {
        printf("Error wc_InitRsaKey(%d): \n", ret);
        return -1;
    }
    ret = wc_InitRng(&rng);
    if (ret < 0)
    {
        printf("Error wc_InitRng(%d): \n", ret);
        return -1;
    }
    ret = wc_RsaSetRNG(&rsaKey, &rng);
    if (ret < 0)
    {
        printf("Error wc_RsaSetRNG(%d): \n", ret);
        return -1;
    }
    idx = 0;
    ret = wc_RsaPrivateKeyDecode(pri, &idx, &rsaKey, pri_size);
    if (ret < 0) {
        printf("Error wc_RsaPrivateKeyDecode(%d): \n", ret);
        return -1;
    }

    /* Generate Signature */
    ret = wc_RsaPSS_Sign(msgd, WC_SHA256_DIGEST_SIZE, sig, sig_size,
                         WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &rsaKey, &rng);
    if (ret < 0) {
        printf("Error wc_RsaPSS_Sign(%d): \n", ret);
        return -1;
    }

    wc_FreeRsaKey(&rsaKey);

    return 0;
}

int main(int argc, char **argv)
{
    FILE *msgf = (FILE *)fopen(argv[1], "rb");
    FILE *sigf = (FILE *)fopen(argv[2], "wb");
    FILE *prif = (FILE *)fopen(argv[3], "rb");

#define MSG_SIZE 4096
    int msg_size;
    byte msg[MSG_SIZE];

#define SIG_SIZE (2048 / 8)
    word32 sig_size;
    byte sig[SIG_SIZE];

#define PRI_DER_SIZE 1200
    int pri_size;
    byte pri[PRI_DER_SIZE];

    /* Read files */
    if (msgf == NULL) {
        printf("File open error: %s\n", argv[1]);
        return -1;
    }
    if (sigf == NULL) {
        printf("File open error: %s\n", argv[2]);
        return -1;
    }
    if (prif == NULL) {
        printf("File open error: %s\n", argv[3]);
        return -1;
    }

    msg_size = fread(msg, 1, MSG_SIZE, msgf);
    printf("\nmsg_size=%d", msg_size);
    dump_bytes(msg, 64);

    pri_size = fread(pri, 1, PRI_DER_SIZE, prif);
    printf("\npri_size=%d", pri_size);
    dump_bytes(pri, 64);

    sig_size = 2048/8;
    if(sign(msg, msg_size, sig, sig_size, pri, pri_size) != 0)
        return -1;

    fwrite(sig, 1, sig_size, sigf);
    printf("\nsig_size=%d", sig_size);
    dump_bytes(sig, sig_size);
}

static int seed = 0;
int MySeed(byte *s, int size)
{
    s[0] = seed++;
    return 0;
}