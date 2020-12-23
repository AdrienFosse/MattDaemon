#include "../headers/Tintin_reporter.h"

using namespace std;

Tintin_reporter::Tintin_reporter()
{
    mkdir("/var/log/matt_daemon", 755);
    log("Matt-daemon is starting", LOG_INFO);
}

void Tintin_reporter::log(std::string str, string log_lvl)
{
    ofstream log_file;
    char datetime[80];

    log_file.open("/var/log/matt_daemon/matt_daemon.log", ios::out | ios::app);
    if (!log_file.is_open())
    {
        exit(EXIT_FAILURE);
    }
    log_file << get_time(datetime) << log_lvl << str << "\n";
    log_file.close();
}

char *Tintin_reporter::get_time(char *dest)
{
    time_t rawtime;
    struct tm * timeinfo;
    
    time (&rawtime);
    timeinfo = localtime (&rawtime);
    strftime (dest, 80,"[%d/%m/%Y-%H:%M:%S]", timeinfo);

    return (dest);
}

Tintin_reporter::~Tintin_reporter()
{
}