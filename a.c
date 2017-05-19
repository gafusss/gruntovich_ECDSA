#include "common.h"

int main(int argc, char *argv[], char *envp[])
{
    if (argc != 4)
    {
        fprintf(stderr, "Usage: a privkeyfile.pem ip port\n");
        return -1;
    }

    char *privpath = argv[1];
    char *ip = argv[2];
    int port = (int)strtol(argv[3], NULL, 10);

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    EVP_PKEY *pkey = NULL;
    EC_KEY *eckey = NULL;
    ECDSA_SIG *sig = NULL;
    struct authmsg_t *msg = NULL;

    {
        FILE *fp = NULL;
        if (!(fp = fopen(privpath, "r")))
        {
            fprintf(stderr, "Could not open private key file\n");
            return -2;
        }

        if (!(pkey = PEM_read_PrivateKey(fp, &pkey, NULL, NULL)))
        {
            fprintf(stderr, "Could not read private key from file\n");
            return -3;
        }

        if (fclose(fp))
        {
            fprintf(stderr, "Could not close private key file\n");
            return -4;
        }
    }

    if (!(eckey = EVP_PKEY_get1_EC_KEY(pkey)))
    {
        fprintf(stderr, "Could not get EC key\n");
        return -5;
    }

    if (EC_KEY_check_key(eckey) != 1)
    {
        fprintf(stderr, "Key sanity check failed\n");
        return -6;
    }

    struct signeddata_t data;

    {
        unsigned char digest[64];
        rhash_library_init();

        data.timestamp = time(NULL);
        data.identifier = B_ID;

        if (rhash_msg(RHASH_SHA3_512, &data, sizeof(struct signeddata_t), digest) < 0)
        {
            fprintf(stderr, "Could not get digest\n");
            return -7;
        }

        if (!(sig = ECDSA_do_sign(digest, 64, eckey)))
        {
            fprintf(stderr, "Could not sign digest\n");
            return -8;
        }

        if (ECDSA_do_verify(digest, 64, sig, eckey) != 1)
        {
            fprintf(stderr, "Signature check failed\n");
            return -9;
        }
    }

    int sigsize = i2d_ECDSA_SIG(sig, NULL);
    int msgsize = sizeof(struct authmsg_t) + sigsize * sizeof(unsigned char);
    if (!(msg = malloc(msgsize)))
    {
        fprintf(stderr, "Could not allocate memory for message\n");
        return -10;
    }

    memcpy(&(msg->data), &data, sizeof(struct signeddata_t));
    unsigned char *p = msg->signature;
    if (!(i2d_ECDSA_SIG(sig, &p)))
    {
        fprintf(stderr, "Could not add signature to message\n");
        return -11;
    }
    msg->signature_size = sigsize;

    int socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1)
    {
        fprintf(stderr, "Could not get socket\n");
        return -12;
    }

    struct sockaddr_in server;
    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if (connect(socket_desc, (struct sockaddr *)&server, sizeof(server)) == -1)
    {
        fprintf(stderr, "Could not connect to B\n");
        return -13;
    }

    if (send(socket_desc, msg, msgsize, 0) != msgsize)
    {
        fprintf(stderr, "Could not send message to B\n");
        return -14;
    }

    close(socket_desc);

    /* Clean up */
    free(msg);

    EVP_PKEY_free(pkey);
    EC_KEY_free(eckey);
    ECDSA_SIG_free(sig);
    
    /* Removes all digests and ciphers */
    EVP_cleanup();

    /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();

    return 0;
}