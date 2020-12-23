#ifndef TINTIN_REPORTER_H
#define TINTIN_REPORTER_H

#include <iostream>
#include <fstream>
#include <time.h>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

#define LOG_INFO " [INFO] => "
#define LOG_TXT " [LOG] => "
#define LOG_ERROR " [ERROR] => "


class Tintin_reporter
{
    public:
        Tintin_reporter();
        // Server(const Server&);
        ~Tintin_reporter();
        // Server &operator=(const Server&);
        void log(std::string str, std::string log_lvl);


    private:
        
        char *get_time(char *dest);
};

#endif