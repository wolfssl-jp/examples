#define WOLFCRYPT_ONLY
#define WOLFSSL_SMALL_STACK

/* RH850 */
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define WOLFSSL_USER_IO
#define NO_DEV_RANDOM
#define SIZEOF_LONG_LONG 8
#define WOLFSSL_LOG_PRINTF
#define NO_DYNAMIC_ARRAY

/* hash.c */
#define NO_MD5
#define NO_SHA
#define NO_DSA

/* random.c */
#define CUSTOM_RAND_GENERATE_SEED(b,c) MySeed()
int MySeed(void);

/* asn.c */
#define NO_CODING
#define NO_CERTS
#define WOLFSSL_ASN_TEMPLATE
#define NO_PKCS8
#define NO_PKCS12
#define NO_ASN_TIME

/* rsa */
#define WC_NO_RSA_OAEP
#define WOLFSSL_RSA_VERIFY_ONLY
#define WOLFSSL_RSA_VERIFY_INLINE
#define WC_NO_HARDEN
#define WC_RSA_BLINDING
#define WC_RSA_PSS
#define NO_INLINE

//#define WOLFSSL_RSA_PUBLIC_ONLY
//#define NO_SIG_WRAPPER
//#define NO_CHECK_PRIVATE_KEY

/* SP */
#define WOLFSSL_HAVE_SP_RSA
#define SP_WORD_SIZE 32
//#define WOLFSSL_SP_SMALL
#define WOLFSSL_SP_NO_MALLOC
