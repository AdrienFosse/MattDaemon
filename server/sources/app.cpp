#include <iostream>
#include "../headers/app.h"

using namespace std;

App App::m_instance=App();

App::App()
{
}

App::App(const App &app)
{
    m_instance = app.m_instance;
}

App::~App()
{
    delete logger;
    delete master_sock;
    delete rsa;
}

App& App::operator=(const App& app)
{
    m_instance = app.m_instance;
    return *this;
}

App& App::Instance()
{
    return m_instance;
}