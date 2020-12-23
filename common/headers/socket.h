#ifndef SOCKET_H
#define SOCKET_H

#define PORT  4242
#define MAX_CLIENT 3

#include <iostream>
#include <vector>
#include "rsa.h"

class Socket
{
    public:
        Socket();
        Socket(int sock);
        Socket(const Socket &socket);
        ~Socket();
        Socket &operator=(const Socket &socket);

        void ConnectToServ(const std::string address);
        void SendMessage(std::vector<char> msg);
        std::vector<char> ReadMessage();
        void bind_to_port();
        int getSocket();

    private:
        void CreateSocket(void);
        int _sock_fd;
        
};

#endif