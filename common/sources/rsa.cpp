#include "../headers/rsa.h"
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>

#include <iostream>
#include <string.h>

using namespace std;

Rsa::Rsa()
{
    GenerateKeyPair();
}

Rsa::Rsa(const Rsa &rsa)
{
    _own_pkey = rsa._own_pkey;
    _own_pub_key = strdup(_own_pub_key);
    _own_priv_key = strdup(_own_priv_key);
}

Rsa::~Rsa()
{
    EVP_PKEY_free(_own_pkey);
}

Rsa& Rsa::operator=(const Rsa &rsa)
{
    _own_pkey = rsa._own_pkey;
    _own_pub_key = strdup(_own_pub_key);
    _own_priv_key = strdup(_own_priv_key);
    return *this;
}

EVP_PKEY            *Rsa::GetOwnPKEY()
{
    return(_own_pkey);
}

char                *Rsa::GetOwnPubKey()
{
    return(_own_pub_key);
}

EVP_PKEY            *Rsa::GeneratePKEY(vector<char> clear_key)
{
    BIO *b;
    EVP_PKEY *side_pkey;

    side_pkey = EVP_PKEY_new();
    b = BIO_new(BIO_s_mem());
    BIO_write(b, clear_key.data(), clear_key.size());
    side_pkey = PEM_read_bio_PUBKEY(b, &side_pkey, NULL, NULL);
    if (side_pkey == NULL){
        printf("ERROR GET PKEY FROM STR\n");
        exit(EXIT_FAILURE);
    }
    return side_pkey;
}

void                Rsa::GenerateKeyPair(void)
{
    EVP_PKEY_CTX    *ctx;
    BIO             *pub_bio;
    BIO             *priv_bio;

    int             res;

    _own_pkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
    {
        std::cout << "Failed to create CTX \n";
        exit(EXIT_FAILURE);
    }
    res = EVP_PKEY_keygen_init(ctx);
    if (res <= 0)
    {
        std::cout << "Failed to init Keygen \n";
        exit(EXIT_FAILURE);
    }
    res = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096);
    if (res <= 0)
    {
        std::cout << "Failed to set Keygen bits \n";
        exit(EXIT_FAILURE);
    }
    _own_pkey = EVP_PKEY_new();

    res = EVP_PKEY_keygen(ctx, &_own_pkey);
    if (res <= 0)
    {
        std::cout << "Failed to generate Keys \n";
        exit(EXIT_FAILURE);
    }

    priv_bio = BIO_new(BIO_s_mem());
    res = PEM_write_bio_PrivateKey(priv_bio, _own_pkey, NULL, NULL, 0, NULL, NULL);
    if (res != 1)
    {
        std::cout << "Unable to write private key to memory \n";
        exit(EXIT_FAILURE);
    }

    BIO_flush(priv_bio);
    BIO_get_mem_data(priv_bio, &_own_priv_key);

    pub_bio = BIO_new(BIO_s_mem());    
    res = PEM_write_bio_PUBKEY(pub_bio, _own_pkey);
    if (res != 1)
    {
        std::cout << "Unable to write public key to menory \n";
        exit(EXIT_FAILURE);
    }
    BIO_flush(pub_bio);
    BIO_get_mem_data(pub_bio, &_own_pub_key);
}

vector<char>        Rsa::EncryptMessage(const vector<char> msg, EVP_PKEY *pkey)
{
    EVP_PKEY_CTX    *curr_ctx;
    vector<char>    string_out;
    char            *msg_in;
    unsigned char   *msg_out;
    size_t          outlen = 0;
    size_t          inlen = 0;

    inlen = (size_t)msg.size();
    msg_in = (char *)malloc(inlen);
    memcpy(msg_in, msg.data(), inlen);
    curr_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (EVP_PKEY_encrypt_init(curr_ctx) <= 0)
    {
        cout << "Unable to init encrypt \n";
    }
    if (EVP_PKEY_CTX_set_rsa_padding(curr_ctx, RSA_PKCS1_PADDING) <= 0)
    {
        cout << "Unable to set padding \n";
    }
    if (EVP_PKEY_encrypt(curr_ctx, NULL, &outlen, (const unsigned char*)msg_in, inlen) <= 0)
    {
        cout << "Unable to get encrypt len \n";
    }
    msg_out = (unsigned char *)OPENSSL_malloc(outlen);
    if (!msg_out)
    {
        cout << "Unable to malloc encrypted msg \n";
    }
    if (EVP_PKEY_encrypt(curr_ctx, msg_out, &outlen, (const unsigned char*)msg_in, inlen) <= 0)
    {
        cout << "Unable to encrypt msg \n";
    }
    string_out.insert(string_out.end(), msg_out, msg_out + outlen);
    free(msg_in);
    OPENSSL_free(msg_out);
    msg_in = NULL;
    msg_out = NULL;
    return (string_out);
}

string              Rsa::DecryptMessage(const vector<char> msg, EVP_PKEY *pkey)
{
    EVP_PKEY_CTX    *curr_ctx;
    string          string_out;
    char            *msg_in;
    unsigned char   *msg_out;
    size_t          outlen = 0;
    size_t          inlen = 0;

    inlen = (size_t)msg.size();
    msg_in = (char *)malloc(inlen);
    memcpy(msg_in, msg.data(), inlen);
    curr_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (EVP_PKEY_decrypt_init(curr_ctx) <= 0)
    {
        cout << "Unable to init decrypt \n";
    }
    if (EVP_PKEY_CTX_set_rsa_padding(curr_ctx, RSA_PKCS1_PADDING) <= 0)
    {
        cout << "Unable to set padding \n";
    }
    if (EVP_PKEY_decrypt(curr_ctx, NULL, &outlen, (const unsigned char*)msg_in, inlen) <= 0)
    {
        cout << "Unable to get decrypt len \n";
    }
    msg_out = (unsigned char *)OPENSSL_malloc(outlen);
    if (!msg_out)
    {
        cout << "Unable to malloc decrypt msg \n";
    }
    if (EVP_PKEY_decrypt(curr_ctx, msg_out, &outlen, (const unsigned char*)msg_in, inlen) <= 0)
    {
        cout << "Unable to decrypt msg" << endl;
    }
    string_out.assign((const char*)msg_out, outlen);
    free(msg_in);
    OPENSSL_free(msg_out);
    msg_in = NULL;
    msg_out = NULL;
    return (string_out);
}