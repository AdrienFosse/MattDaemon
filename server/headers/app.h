#ifndef APP_H
#define APP_H

#include "../headers/Tintin_reporter.h"
#include "../../common/headers/socket.h"
#include "../../common/headers/aes.h"

#define ADDRESS  "127.0.0.1"
#define PORT     4242

class App 
{
    public:
        static App& Instance();
        Tintin_reporter *logger;
        Socket          *master_sock;
        Rsa             *rsa;
        int             nb_client;

    private:
        static App m_instance;
        App();
        App(const App& app);
        ~App();
        App& operator= (const App& app);
};
#endif