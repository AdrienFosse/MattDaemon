#ifndef SHELL_H
#define SHELL_H
#include <unistd.h>
#include <iostream>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fstream>
#include <cerrno>
#include <sys/file.h>
#include <csignal>
#include <string>
#include <cstring>
#include <sys/types.h>
#include <sys/wait.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <thread>

#define READ_END 0
#define WRITE_END 1

class Shell
{
    public:
        std::string     StdOut;
        int             infd[2] = {0, 0};
        int             outfd[2] = {0, 0};
        int             errfd[2] = {0, 0};

        void execute();
        Shell();
        ~Shell();
    private:
        int             _pid;

};

#endif