#include "common.h"

int main(int argc, char *argv[], char *envp[])
{
    if ((argc < 4) || (argc > 5))
    {
        fprintf(stderr, "Usage: a pubkeyfile.pem port timeout [single_run?]\n");
        return -1;
    }

    char *pubpath = argv[1];
    int port = (int)strtol(argv[2], NULL, 10);
    int timeout = (int)strtol(argv[3], NULL, 10);
    int single = argc - 4;

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    EVP_PKEY *pkey = NULL;
    EC_KEY *eckey = NULL;

    {
        FILE *fp = NULL;
        if (!(fp = fopen(pubpath, "r")))
        {
            fprintf(stderr, "Could not open public key file\n");
            return -2;
        }

        if (!(pkey = PEM_read_PUBKEY(fp, &pkey, NULL, NULL)))
        {
            fprintf(stderr, "Could not read public key from file\n");
            return -3;
        }

        if (fclose(fp))
        {
            fprintf(stderr, "Could not close public key file\n");
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

    rhash_library_init();

    int socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1)
    {
        fprintf(stderr, "Could not get socket\n");
        return -7;
    }

    struct sockaddr_in server;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if (bind(socket_desc, (struct sockaddr *)&server, sizeof(server)) == -1)
    {
        fprintf(stderr, "Could not bind socket\n");
        return -8;
    }

    if (listen(socket_desc, 1) == -1)
    {
        fprintf(stderr, "Could not listen on socket\n");
        return -9;
    }

    struct sockaddr_in client;
    socklen_t c = sizeof(struct sockaddr_in);

    int client_socket;

    char b[1000];
    unsigned char digest[64];
    while ((client_socket = accept(socket_desc, (struct sockaddr *)&client, &c)))
    {
        if (client_socket != -1)
        {
            printf("[%s:%d]", inet_ntoa(client.sin_addr), client.sin_port);
            struct authmsg_t *msg = (struct authmsg_t *)&b;
            int size = recv(client_socket, b, 1000, 0);
            if ((size == -1) || (size < sizeof(struct authmsg_t)) || ((msg->signature_size + sizeof(struct authmsg_t)) != size))
            {
                fprintf(stderr, "Error receiving message or message size mismatch, ignoring\n");
                if (single) return -100;
                else continue;
            }
            if (recv(client_socket, b, 1000, 0) != 0)
            {
                fprintf(stderr, "Could not receive FIN, ignoring\n");
                if (single) return -101;
                else continue;
            }
            close(client_socket);
            int32_t timestamp = time(NULL);
            if (msg->data.identifier != B_ID)
            {
                fprintf(stderr, "Wrong identifier in message, ignoring\n");
                if (single) return -102;
                else continue;
            }

            {

                if (rhash_msg(RHASH_SHA3_512, &(msg->data), sizeof(struct signeddata_t), digest) < 0)
                {
                    fprintf(stderr, "Could not get digest\n");
                    return -10;
                }

                ECDSA_SIG *sig = NULL;
                const unsigned char * dersig = msg->signature;
                if (!(sig = d2i_ECDSA_SIG(&sig, &dersig, msg->signature_size)))
                {
                    fprintf(stderr, "Could not read signature\n");
                    return -11;
                }

                if (ECDSA_do_verify(digest, 64, sig, eckey) != 1)
                {
                    printf(" sign = FAILED\n");
                    ECDSA_SIG_free(sig);
                    if (single) return -103;
                    else continue;
                }

                ECDSA_SIG_free(sig);
            }
            int32_t delta = timestamp - msg->data.timestamp;
            printf(" sign = ok, delta = %d", delta);
            if ((delta >= 0) && delta <= timeout)
            {
                printf(", auth = ok\n");
            }
            else
            {
                printf(", auth = FAILED\n");
            }
        }
        else
        {
            fprintf(stderr, "Could not get client socket, ignoring\n");
        }
        if (single)
        {
            return 0;
        }
    }

    close(socket_desc);

    /* Clean up */

    EVP_PKEY_free(pkey);
    EC_KEY_free(eckey);
    
    /* Removes all digests and ciphers */
    EVP_cleanup();

    /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();

    return 0;
}