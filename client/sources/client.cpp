#include "../headers/client.h"

#include "string.h"
#include <openssl/aes.h>

using namespace std;

Client::Client()
{
    _rsa = new Rsa();
    _own_pkey = _rsa->GetOwnPKEY();
    _pub_key = _rsa->GetOwnPubKey();
}

Client::Client(const Client &client)
{
    _rsa = new Rsa(*client._rsa);
}

Client::~Client()
{
    delete(_rsa);
    delete(_aes);
    delete(_sockt);
}

Client& Client::operator=(const Client& client)
{
    _rsa = client._rsa;
    _own_pkey = (client._rsa)->GetOwnPKEY();
    _pub_key = (client._rsa)->GetOwnPubKey();

    return *this;
}

void                Client::EstablishConnection(const string address)
{
    _sockt = new Socket();
    _sockt->ConnectToServ(address);
}

void                Client::SendPubKey()
{
    vector<char>    msg_to_send;

    msg_to_send.insert(msg_to_send.end(), _pub_key, _pub_key + strlen(_pub_key));
    _sockt->SendMessage(msg_to_send);
}

void                Client::GetServPubKey()
{
    vector<char>    msg_receive;

    msg_receive = _sockt->ReadMessage();
    _serv_pkey = _rsa->GeneratePKEY(msg_receive);
}

void                Client::SendMessageToServ(unsigned char *msg)
{
    vector<char>    tmp;
    int             cryp_len;
    int             plain_len;
    unsigned char   *crypt_msg;

    plain_len = strlen((const char *)msg);
    crypt_msg = new unsigned char[plain_len + AES_BLOCK_SIZE];
    cryp_len = _aes->encrypt(msg, plain_len, crypt_msg);
    tmp.insert(tmp.end(), crypt_msg, crypt_msg + cryp_len);
    _sockt->SendMessage(tmp);
    delete [] crypt_msg;
}

string              Client::RecieveMessageRsaType()
{
    vector<char>    msg_receive;
    string          clear_msg;
    
    msg_receive = _sockt->ReadMessage();
    clear_msg = _rsa->DecryptMessage(msg_receive, _own_pkey);
    return(clear_msg);
}

string              Client::RecieveMessageAesType()
{
    vector<char>    msg_receive;
    unsigned char   *clear_msg;
    string          msg;
    
    msg_receive = _sockt->ReadMessage();
    clear_msg = new unsigned char[msg_receive.size()];
    _aes->decrypt((unsigned char *)msg_receive.data(), msg_receive.size(), clear_msg);
    msg = std::string(reinterpret_cast<char*>(clear_msg));
    return(msg);
}

void                Client::GetSymKey()
{
    std::string key;
    std::string iv;
    
    key = RecieveMessageRsaType();
    iv = RecieveMessageRsaType();
    _aes = new Aes((unsigned char *)key.c_str(), (unsigned char *)iv.c_str());
}

int                 Client::LoginToServ(string password)
{
    string          msg_receive;

    SendMessageToServ((unsigned char *)password.c_str());
    msg_receive = RecieveMessageAesType();
    if (memcmp(msg_receive.c_str(), "OK", 2) == 0)
        return (1);
    return (0);
}