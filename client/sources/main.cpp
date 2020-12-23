#include "../headers/client.h"
#include "../../common/headers/socket.h"
#include "../../common/headers/rsa.h"
#include <iostream>
#include <string.h>

using namespace std;

void                Login(Client *client)
{
    int             isLog = 0;
    string          user_input;

    while (isLog == 0)
    {
        user_input.clear();
        cout <<"Password: ";
        getline (cin, user_input);
        if (user_input.empty())
        {
            cout << "Please enter a password" << endl;
            continue;
        }
        else
        {
            if (client->LoginToServ(user_input) == 1)
            {
                cout << "Successfully connected" << endl;
                isLog = 1;
                break;
            }
            else
            {
                cout << "Incorrect password, sorry =)" << endl;
                delete(client);
                exit (EXIT_FAILURE);
            }
        }
    }
}

void                manage_shell(Client *client, const char *cmd)
{
    string      msg; 
    client->SendMessageToServ((unsigned char *)cmd);
    msg = client->RecieveMessageAesType();
    if (msg.compare("ooKK") != 0)
        cout << msg << endl;
}


int                 main(int argc, char *argv[])
{
    Client          *client;
    string          address;
    string          user_input;
    string          msg;
    string          prompt = "Message: ";

    if (argc != 2)
    {
        cout << "Usage: ./Ben_AFK <Server Address>" << endl;
        exit (-1);
    }
    address.assign(argv[1]);
    client = new Client();
    client->EstablishConnection(address);
    client->SendPubKey();
    client->GetServPubKey();
    client->GetSymKey();
    Login(client);
    cout << prompt;
    while (getline(cin, user_input))
    {
        if (user_input.empty())
        {
            cout << "Please enter a message" << endl;
        }
        else if (user_input.compare("shell") == 0)
        {
            prompt.assign("> ", 2);
            client->SendMessageToServ((unsigned char *)"shell");
        }
        else
        {
            if (prompt.compare("> ") == 0)
            {
                manage_shell(client, user_input.c_str());
                if (user_input.compare("quit") == 0)
                    prompt.assign("Message: ", 9);
            }
            else
            {
                client->SendMessageToServ((unsigned char *)user_input.c_str());
                if (user_input.compare("quit") == 0)
                    break;
            }
                
        }
        cout << prompt;
        user_input.clear();
    }
    delete(client);
    return (0);
}