#include "../headers/session.h"

using namespace std;

Session::Session()
{
}

Session::Session(Socket *socket)
{
    sock = socket;
}

Session::Session(const Session &session)
{
    sock = session.sock;
    aes = session.aes;
}

Session::~Session()
{
    delete sock;
    delete aes;
}

Session& Session::operator=(const Session &session)
{
        sock = session.sock;
        aes = session.aes;
        return *this;
}