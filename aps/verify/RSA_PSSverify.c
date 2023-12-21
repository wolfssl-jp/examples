
#include <stdio.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/sha256.h>

static void dump_bytes(const byte *p, word32 len)
{
    printf("\n");
    for (; len; len--, p++) {
        if (((unsigned long)p & 0x07) == 0) {
            printf("\n");
        }
        printf("%02x ", *p);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    wc_Sha256 sha256;

    FILE *msgf = (FILE *)fopen(argv[1], "rb");
    FILE *sigf = (FILE *)fopen(argv[2], "rb");
    FILE *pubf = (FILE *)fopen(argv[3], "rb");

#define MSG_SIZE (4096*100)
    int msg_size;
    byte msg[MSG_SIZE];

    byte *msg_p;
    #define MSG_BLOCK 64

    #define SIG_SIZE (3072/8)
    int sig_size;
    byte sig[SIG_SIZE];

    #define PUB_DER_SIZE 512
    int pub_size;
    byte pub[PUB_DER_SIZE];


    byte msgd[WC_SHA256_DIGEST_SIZE];

    byte *decSig;

    RsaKey rsaKey;
    word32 idx = 0;
    int ret;

    /* Read files */
    if (msgf == NULL) {
        printf("File open error: %s\n", argv[1]);
        return -1;
    }
    if (sigf == NULL) {
        printf("File open error: %s\n", argv[2]);
        return -1;
    }
    if (pubf == NULL) {
        printf("File open error: %s\n", argv[3]);
        return -1;
    }

    msg_size = fread(msg, 1, MSG_SIZE, msgf);
    printf("\nmsg_size=%d", msg_size);
    dump_bytes(msg, 256);

    memset(sig, 0, SIG_SIZE);
    sig_size = fread(sig, 1, SIG_SIZE, sigf);
    printf("\nsig_size=%d", sig_size);
    dump_bytes(sig, SIG_SIZE);

    pub_size = fread(pub, 1, PUB_DER_SIZE, pubf);
    printf("\npub_size=%d", pub_size);
    dump_bytes(pub, pub_size);

    /* Message Hash */
    ret = wc_InitSha256(&sha256);
    if(ret < 0) {
        printf("Error wc_InitSha256(%d): \n", ret);
        return -1;
    }

    for(msg_p = msg; msg_size >= MSG_BLOCK; 
                msg_size -= MSG_BLOCK, msg_p += MSG_BLOCK) {
        ret = wc_Sha256Update(&sha256, msg_p, MSG_BLOCK);
        if(ret < 0) {
            printf("Error wc_Sha256Update(%d): \n", ret);
            return -1;
        }
    }
    if(msg_size > 0)
        ret = wc_Sha256Update(&sha256, msg_p, MSG_BLOCK);
    if(ret < 0) {
        printf("Error wc_Sha256Update(%d): \n", ret);
        return -1;
    }

    ret = wc_Sha256Final(&sha256, msgd);
    if(ret < 0) {
        printf("Error wc_Sha256Final(%d): \n", ret);
        return -1;
    }

    printf("\nHash");
    dump_bytes(msgd, 32);

    /* Set up public key */
    ret = wc_InitRsaKey(&rsaKey, NULL);
    if(ret < 0) {
        printf("Error wc_InitRsaKey(%d): \n", ret);
        return -1;
    }

    ret = wc_RsaPublicKeyDecode(pub, &idx, &rsaKey, pub_size);
    if (ret < 0)
    {
        printf("Error wc_RsaPublicKeyDecode(%d): \n", ret);
        return -1;
    }

    /* Verify Sigature */
    ret = wc_RsaPSS_VerifyCheckInline(sig, sig_size, &decSig, msgd,
                WC_SHA256_DIGEST_SIZE, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &rsaKey);
    if (ret < 0)
    {
        printf("Error wc_RsaSSL_VerifyInline(%d): \n", ret);
        return -1;
    }
    printf("\nVerified(%d)", ret);

    /* VerifyCheckInline uses sig area as an working buffer. 
                                            Read the signature again */
    fseek(sigf, 0, SEEK_SET);
    sig_size = fread(sig, 1, SIG_SIZE, sigf);

    /* invalidate the signature */
    sig[0] = 0;

    ret = wc_RsaPSS_VerifyCheckInline(sig, sig_size, &decSig, msgd,
        WC_SHA256_DIGEST_SIZE, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &rsaKey);

    printf("\nret = %d\n", ret);

    return 0;
}

/* For dummy seed. Verify operation doesn't use RNG */
int MySeed(void)
{
    static int i;
    return i++;
}