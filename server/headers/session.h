#ifndef SESSION_H
#define SESSION_H

#include "../../common/headers/socket.h"
#include "../../common/headers/aes.h"


class Session 
{
    public:
        Socket          *sock;
        Aes             *aes;
        
        Session();
        Session(Socket *socket);
        Session (const Session& session);
        ~Session();
        Session& operator= (const Session& session);

    private:

};
#endif