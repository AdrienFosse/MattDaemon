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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <thread>


#include "../headers/server.h"
#include "../headers/Tintin_reporter.h"
#include "../headers/app.h"
#include "../headers/session.h"
#include "../headers/shell.h"



void sig_handler(int signum)
{
    App& app=App::Instance();

    app.logger->log("Signal receive :" + std::to_string(signum), LOG_INFO);
    quit();
}

void daemonize(Tintin_reporter *logger)
{
    pid_t pid;
    pid_t sid;

    pid = fork();
    if (pid == -1)
    {
        logger->log("Failed to daemonize", LOG_ERROR);        
        exit(EXIT_FAILURE);
    }
    else if (pid > 0)
        exit(EXIT_SUCCESS);
        
    //Child permissions 777
    umask(0);
    //Child Lead
    sid = setsid();
    if (sid == -1)
        exit(EXIT_FAILURE);
    chdir("/");
    
    close(0);
    close(1);
    close(2);
    logger->log("Successfully daemonized", LOG_INFO);
}

void wait_connexion()
{
    uint32_t		    cslen;
	Socket				*new_sock;
    Session             *session;
    App&                app=App::Instance();
	struct sockaddr_in	csin;
    
    app.nb_client = 0;
	while ((new_sock = new Socket(accept(app.master_sock->getSocket(), (struct sockaddr*)&csin, &cslen)))->getSocket() != -1)
	{
        app.logger->log("New client from socket", LOG_INFO);
        if (app.nb_client >= 3)
        {
            delete new_sock;
            app.logger->log("Max number of client is reached, we drop connection", LOG_INFO);
            continue;
        }
        app.nb_client++;
        session = new Session(new_sock);
		std::thread(&main_process, session).detach();
        app.logger->log("thread started", LOG_INFO);
	}
    app.logger->log("Server quit\n", LOG_INFO);
}

void init()
{
    App& app=App::Instance();

    app.master_sock = new Socket();
    app.master_sock->bind_to_port();
    app.logger = new Tintin_reporter();
    app.logger->log("Server created", LOG_INFO);

    app.rsa = new Rsa();
    app.logger->log("Pub/Priv Keys created", LOG_INFO);
    daemonize(app.logger);

    signal(SIGABRT, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGINT, sig_handler);
    signal(SIGSEGV, sig_handler);
    signal(SIGTERM, sig_handler);
}

int             main(void)
{
    int fd;

    if (getuid() != 0)
    {
        std::cout << "Programm need to be run as root " << '\n';
        exit(EXIT_FAILURE);
    }
    fd = open("/var/lock/matt_daemon.lock", O_CREAT);
    if (fd == -1)
    {
        std::cout << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
    if (flock(fd, LOCK_EX | LOCK_NB) == -1)
    {
        std::cout << "Lock file :" << strerror(errno) << std::endl;
        std::cout << "Matt_daemon is already started, program quit" << std::endl;
        exit(EXIT_FAILURE);
    }
    init();
    wait_connexion();
    return (0);
}