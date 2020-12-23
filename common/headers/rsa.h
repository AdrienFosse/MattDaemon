#ifndef RSA_H
#define RSA_H

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/bio.h>

#include <iostream>
#include <vector>

class Rsa
{
    public:
        Rsa();
        Rsa(const Rsa &rsa);
        ~Rsa();
        Rsa &operator=(const Rsa &rsa);
        std::vector<char>   EncryptMessage(std::vector<char> msg, EVP_PKEY *pkey);
        std::string         DecryptMessage(std::vector<char> msg, EVP_PKEY *pkey);
        EVP_PKEY            *GetOwnPKEY();
        EVP_PKEY            *GeneratePKEY(std::vector<char> clear_key);
        char                *GetOwnPubKey();
        void                SendMessageToServ();
    
    private:
        void                GenerateKeyPair(void);
        EVP_PKEY            *_own_pkey;
        char                *_own_pub_key;
        char                *_own_priv_key;
};

#endif