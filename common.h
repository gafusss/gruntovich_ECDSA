#ifndef crypto_gr_common
#define crypto_gr_common 1


#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <openssl/ec.h>
#include <openssl/bn.h>

#include <openssl/pem.h>

#include <openssl/ecdsa.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <time.h>
#include <stdint.h>

#include <rhash.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define B_ID 'b'

struct __attribute__((__packed__)) signeddata_t
{
    int32_t timestamp;
    char identifier;
};

struct __attribute__((__packed__)) authmsg_t
{
    struct signeddata_t data;
    int32_t signature_size;
    unsigned char signature[];
};

#endif