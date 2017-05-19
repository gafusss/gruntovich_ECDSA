#include "common.h"

int main(int argc, char *argv[], char *envp[])
{
    if ((argc < 2) || (argc > 3))
    {
        fprintf(stderr, "Usage: gen privoutfile.pem [puboutfile.pem]\n");
        return -1;
    }

    char *privpath = argv[1];
    char *pubpath = argv[2];

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* ... Do some crypto stuff here ... */

    EVP_PKEY_CTX *kctx = NULL, *pctx = NULL;
    EVP_PKEY *params = NULL, *pkey = NULL;
    EC_KEY *eckey = NULL;

    if (!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)))
    {
        fprintf(stderr, "Could not create param generation context\n");
        return -2;
    }

    if (EVP_PKEY_paramgen_init(pctx) != 1)
    {
        fprintf(stderr, "Could not init param generation\n");
        return -3;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp521r1) != 1)
    {
        fprintf(stderr, "Could not set curve\n");
        return -4;
    }

    if (EVP_PKEY_paramgen(pctx, &params) != 1)
    {
        fprintf(stderr, "Could not generate params\n");
        return -5;
    }

    if (!(kctx = EVP_PKEY_CTX_new(params, NULL)))
    {
        fprintf(stderr, "Could not create key generation context\n");
        return -6;
    }

    if (EVP_PKEY_keygen_init(kctx) != 1)
    {
        fprintf(stderr, "Could not init key generation\n");
        return -7;
    }

    if (EVP_PKEY_keygen(kctx, &pkey) != 1)
    {
        fprintf(stderr, "Could not generate key\n");
        return -8;
    }

    if (!(eckey = EVP_PKEY_get1_EC_KEY(pkey)))
    {
        fprintf(stderr, "Could not get generated EC key\n");
        return -9;
    }

    if (EC_KEY_check_key(eckey) != 1)
    {
        fprintf(stderr, "Key sanity check failed\n");
        return -10;
    }

    {
        FILE *fp = NULL;
        if (!(fp = fopen(privpath, "w")))
        {
            fprintf(stderr, "Could not open private key file\n");
            return -11;
        }

        if (PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL) != 1)
        {
            fprintf(stderr, "Could not write private key to file\n");
            return -12;
        }

        if (fclose(fp))
        {
            fprintf(stderr, "Could not close private key file\n");
            return -13;
        }
        
        if (pubpath != NULL)
        {
            if (!(fp = fopen(pubpath, "w")))
            {
                fprintf(stderr, "Could not open public key file\n");
                return -14;
            }

            if (PEM_write_PUBKEY(fp, pkey) != 1)
            {
                fprintf(stderr, "Could not write public key to file\n");
                return -15;
            }

            if (fclose(fp))
            {
                fprintf(stderr, "Could not close public key file\n");
                return -16;
            }
        }
    }

    /* Clean up */

    EC_KEY_free(eckey);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(params);

    /* Removes all digests and ciphers */
    EVP_cleanup();

    /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();

    return 0;
}