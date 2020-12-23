#ifndef CLIENT_H
#define CLIENT_H

#include "../../common/headers/rsa.h"
#include "../../common/headers/aes.h"
#include "../../common/headers/socket.h"

#include <openssl/evp.h>
#include <iostream>

class Client
{
    public:
        Client();
        Client(const Client &client);
        ~Client();
        Client          &operator=(const Client &client);
        void            EstablishConnection(const std::string address);
        void            GetServPubKey();
        void            SendPubKey();
        void            SendMessageToServ(unsigned char *msg);
        std::string     RecieveMessageRsaType();
        std::string     RecieveMessageAesType();
        void            GetSymKey();
        int             LoginToServ(std::string password);

    private:
        EVP_PKEY        *_serv_pkey;
        EVP_PKEY        *_own_pkey;
        char            *_pub_key;
        Rsa             *_rsa;
        Socket          *_sockt;
        Aes             *_aes;
};

#endif