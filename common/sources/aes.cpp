#include <string.h>
#include <string>
#include <random>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "../headers/aes.h"


Aes::Aes()
{
    std::string tmp;

    tmp = random_string(KEY_SIZE);
    _key = (unsigned char *)strdup((char *)tmp.c_str());
    tmp = random_string(IV_SIZE);
    _IV = (unsigned char *)strdup((char *)tmp.c_str());
}

Aes::Aes(unsigned char *key, unsigned char *IV)
{
    _key = (unsigned char *)strdup((char *)key);
    _IV = (unsigned char *)strdup((char *)IV);
}

Aes::Aes(const Aes &aes)
{
    _key = (unsigned char *)strdup((char *)aes._key);
    _IV = (unsigned char *)strdup((char *)aes._IV);
}

Aes::~Aes()
{
    free(_key);
    free(_IV);
}

Aes& Aes::operator=(const Aes &aes)
{
    _key = (unsigned char *)strdup((char *)aes._key);
    _IV = (unsigned char *)strdup((char *)aes._IV);
    return *this;
}

void Aes::handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    // abort();
}

int Aes::encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, _key, _IV))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int Aes::decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, _key, _IV))
        handleErrors();

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;
    plaintext[plaintext_len] = '\0';

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

std::string Aes::random_string(size_t length)
{
    const std::string CHARACTERS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    std::random_device random_device;
    std::mt19937 generator(random_device());
    std::uniform_int_distribution<> distribution(0, CHARACTERS.size() - 1);

    std::string random_string;

    for (std::size_t i = 0; i < length; ++i)
    {
        random_string += CHARACTERS[distribution(generator)];
    }

    return random_string;
}
