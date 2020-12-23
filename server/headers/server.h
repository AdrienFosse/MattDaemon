#ifndef SERVER_H
#define SERVER_H

#include "../headers/Tintin_reporter.h"
#include "../../common/headers/socket.h"
#include "../../common/headers/aes.h"
#include "../headers/session.h"




void            main_process(Session *session);
bool            login(Session *session);
void            sendEncryptedMessage(unsigned char *msg, Session *session);
int             manage_message(Socket *sock, std::string msg);
void            key_exchange(Session *session);
int             start_shell(Session *session);
unsigned char   *getMessage(Session *session);
void 			quit();



#endif