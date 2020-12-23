#include "../headers/socket.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <iostream>
#include <string.h>
#include <vector>
#include <unistd.h>

using namespace std;

Socket::Socket()
{
    CreateSocket();
}

Socket::Socket(int sock)
{
    _sock_fd = sock;
}

Socket::Socket(const Socket &socket)
{
    _sock_fd = socket._sock_fd;
}

Socket::~Socket()
{
    if (_sock_fd > 0)
        close(_sock_fd);
}

Socket& Socket::operator=(const Socket &socket)
{
    _sock_fd = socket._sock_fd;
    return *this;
}

void Socket::CreateSocket(void)
{
  	struct protoent		*proto;

    proto = getprotobyname("tcp");
	if (proto == 0)
    {
        printf("Missing protocol\n");
        exit(EXIT_FAILURE);
    }
        
    _sock_fd = socket(AF_INET, SOCK_STREAM, proto->p_proto);
    if (_sock_fd == -1)
    {
        printf("Unable to create client socket\n");
        exit(EXIT_FAILURE);
    }
}

void Socket::bind_to_port()
{
    struct sockaddr_in	sin;
    int                 param = 1;

    sin.sin_family = AF_INET;
	sin.sin_port = htons(PORT);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	if (setsockopt(_sock_fd, SOL_SOCKET, SO_REUSEADDR, &param, sizeof(int)) < 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    if (::bind(_sock_fd, (const struct sockaddr*)&sin, sizeof(sin)) == -1)
	{
        printf("%s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	listen(_sock_fd, MAX_CLIENT);
}

void Socket::ConnectToServ(const std::string address)
{
    struct sockaddr_in server_addr;

    server_addr.sin_addr.s_addr = inet_addr(address.c_str());
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (connect(_sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        printf("Unable to establish connection to server\n");
        exit(EXIT_FAILURE);
    }
}

int Socket::getSocket()
{
    return (_sock_fd);
}

void Socket::SendMessage(vector<char> msg)
{
    int size = msg.size();
    int ret;

    //send size
    ret = send(_sock_fd, &size, sizeof(int), 0);
    if (ret == -1){
        printf("TAMERE SEND\n");
        printf("%s\n", strerror(errno));

    }
   //send msg
    ret = send(_sock_fd, msg.data(), size, 0);

    if (ret == -1){
        printf("TAMERE SEND 2\n");
        printf("%s\n", strerror(errno));
    }
}

std::vector<char>   Socket::ReadMessage()
{
    int size;
    int ret;
    int curr_size = 0;
    char *msg_recv;
    std::vector<char> msg;

    // receive size
    ret = recv(_sock_fd, &size, sizeof(int), 0);
    if (ret <= 0){
        return (msg);
    }
    //receive msg
    msg_recv = (char *)malloc(sizeof(char) * size);
    bzero(msg_recv, size);
    if (msg_recv != NULL)
    {
        while (curr_size < size)
        {
            ret = recv(_sock_fd, msg_recv, size - curr_size, 0);

            if (ret == -1){
                printf("TAMERE SEND 2\n");
                return (msg);
            }
            msg.insert(msg.end(), msg_recv, ret + msg_recv);            
            curr_size += ret;
        }
        free(msg_recv);
    }
    return(msg);
}
