#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <thread>
#include <string.h>
#include <vector>
#include <algorithm>
#include <openssl/md5.h>
#include <iomanip>
#include <sstream>
#include <openssl/aes.h>
#include <sys/select.h>


#include "../headers/server.h"
#include "../headers/app.h"
#include "../headers/session.h"
#include "../headers/shell.h"


void 					quit()
{
	int 				fd;
	int 				ret = EXIT_SUCCESS;
    App& 				app = App::Instance();

    fd = open("/var/lock/matt_daemon.lock", O_CREAT);
    if (fd == -1)
    {
        app.logger->log("Error on open lock :", LOG_ERROR);
        app.logger->log(strerror(errno), LOG_ERROR);
        ret = EXIT_FAILURE;
    }
    if (flock(fd, LOCK_UN) == -1)
    {
        app.logger->log("Error on unlock :", LOG_ERROR);
        app.logger->log(strerror(errno), LOG_ERROR);
        ret = EXIT_FAILURE;
    }
    close(fd);
    if (remove("/var/lock/matt_daemon.lock") != 0)
    {
        app.logger->log("Error on remove lock file :", LOG_ERROR);
        app.logger->log(strerror(errno), LOG_ERROR);
        ret = EXIT_FAILURE;
    }
    app.logger->log("Matt_daemon exit :", LOG_INFO);
    delete app.logger;
	delete app.master_sock;
    delete app.rsa;

    exit(ret);
}

void					key_exchange(Session *session)
{
	std::vector<char> 	msg;
	EVP_PKEY    		*client_pkey;
	App&        		app=App::Instance();


	msg = session->sock->ReadMessage();
	client_pkey = app.rsa->GeneratePKEY(msg);
	if (client_pkey == NULL){
		app.logger->log("INVALID CLIENT KEY", LOG_ERROR);
	}
	app.logger->log("Client pubkey received", LOG_INFO);

	msg.clear();
	msg.insert(msg.end(), app.rsa->GetOwnPubKey(), app.rsa->GetOwnPubKey() + strlen(app.rsa->GetOwnPubKey()));
    session->sock->SendMessage(msg);
	app.logger->log("Server pubkey sent", LOG_INFO);

	msg.clear();
	msg.insert(msg.end(), session->aes->_key, session->aes->_key + KEY_SIZE);

	msg = app.rsa->EncryptMessage(msg, client_pkey);
	session->sock->SendMessage(msg);
	app.logger->log("encrypted symmetric key sent ", LOG_INFO);

	msg.clear();
	msg.insert(msg.end(), session->aes->_IV, session->aes->_IV + IV_SIZE);

	msg = app.rsa->EncryptMessage(msg, client_pkey);
	session->sock->SendMessage(msg);
	app.logger->log("encrypted symmetric IV sent", LOG_INFO);
}

void sendEncryptedMessage(unsigned char *msg, Session *session)
{
	std::vector<char>    tmp;
    int             cryp_len;
    int             plain_len;
    unsigned char   *crypt_msg;

    plain_len = strlen((const char *)msg);
    crypt_msg = new unsigned char[plain_len + AES_BLOCK_SIZE];
    cryp_len = session->aes->encrypt(msg, plain_len, crypt_msg);
    tmp.insert(tmp.end(), crypt_msg, crypt_msg + cryp_len);
    session->sock->SendMessage(tmp);
    delete [] crypt_msg;
}

bool login(Session *session)
{
	std::vector<char> 	msg_cipher;
	std::string			clear_msg;
	unsigned char 		hash[MD5_DIGEST_LENGTH];
	unsigned char 		hex_hash[MD5_DIGEST_LENGTH * 4];
	unsigned char 		*msg;
	const unsigned char pass[] = "098f6bcd4621d373cade4e832627b4f6";

	msg_cipher = session->sock->ReadMessage();
	if (msg_cipher.empty())
		return false;

	msg = new unsigned char[msg_cipher.size()];
	session->aes->decrypt((unsigned char *)msg_cipher.data(), msg_cipher.size(), msg);
	clear_msg = std::string(reinterpret_cast<char*>(msg));

	MD5((unsigned char*)clear_msg.c_str(), clear_msg.size(), hash);
	for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
	{
		snprintf((char *)hex_hash + (i * 2), 3, "%02x", hash[i]);
	}

	delete [] msg;
	if (memcmp(hex_hash, pass, MD5_DIGEST_LENGTH) == 0)
	{
		sendEncryptedMessage((unsigned char *)"OK", session);
		return true;
	}
	else{
		sendEncryptedMessage((unsigned char *)"NOT OK", session);
		return false;
	}
}

int start_shell(Session *session)
{
	App& 					app=App::Instance();

	Shell 					*shell = new Shell();
	unsigned char 			*cmd;
	size_t bytes;
	std::array<char, 4096> 	buffer; //pas ouf sur la stack
	fd_set 					rfds;
    struct timeval 			tv;
    int 					retval;

	app.logger->log("Start shell", LOG_INFO);
	while (true)
	{
		bytes = 0;
		cmd = getMessage(session);
		if (cmd == NULL)
			break;
		if (strcmp((const char*)cmd, (const char*)"quit") == 0)
		{
			sendEncryptedMessage((unsigned char *)"ooKK", session);
			break;
		}
		write(shell->infd[WRITE_END], cmd, strlen((char *)cmd));
		write(shell->infd[WRITE_END], "\n", 1);
		app.logger->log("Send command to shell", LOG_INFO);
		delete cmd;

		FD_ZERO(&rfds);
		FD_SET(shell->outfd[READ_END], &rfds);
		FD_SET(shell->errfd[READ_END], &rfds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		retval = select(std::max(shell->outfd[READ_END], shell->errfd[READ_END]) + 1, &rfds, NULL, NULL, &tv);
		if (retval == -1)
		{
			perror("select()");
			delete shell;
			return(-1);
		}
		else if (retval)
		{
			/*
			*Check if stdout have something, we also take stderr if ready
			*/
			if (FD_ISSET(shell->outfd[READ_END], &rfds))
			{
				do
				{
					bytes = read(shell->outfd[READ_END], buffer.data(), buffer.size());
					if (bytes > 0)
							shell->StdOut.append(buffer.data(), bytes);
					if (bytes < buffer.size())
						break;
				}
				while(bytes > 0);
			}
			if (FD_ISSET(shell->errfd[READ_END], &rfds))
			{
				do
				{
					bytes = read(shell->errfd[READ_END], buffer.data(), buffer.size());
					if (bytes > 0)
							shell->StdOut.append(buffer.data(), bytes);
					if (bytes < buffer.size())
						break;
				}
				while(bytes > 0);
			}
			if (shell->StdOut.size() > 0)
				sendEncryptedMessage((unsigned char *)shell->StdOut.c_str(), session);
		}
		else{
			sendEncryptedMessage((unsigned char *)"ooKK", session);
		}
		shell->StdOut.erase();
	}
	app.logger->log("Shell closed", LOG_INFO);
	delete shell;
	return 0;
}

int manage_message(Session *session, std::string msg)
{
	App& 			app=App::Instance();

	if (msg.compare("quit") == 0)
	{
		if (app.nb_client == 1)
		{
			app.logger->log("Matt daemon is quitting", LOG_INFO);
			quit();
		}
		else
			return (-1);
	}
	else if (msg.compare("shell") == 0)
		return start_shell(session);
	else
		app.logger->log(msg, LOG_TXT);
	return (0);
}

unsigned char *getMessage(Session *session)
{
	std::vector<char> 		msg_cipher;
	unsigned char 			*msg;

	msg_cipher = session->sock->ReadMessage();
	if (msg_cipher.empty())
		return NULL;
	msg = new unsigned char[msg_cipher.size()];
	session->aes->decrypt((unsigned char *)msg_cipher.data(), msg_cipher.size(), msg);

	return msg;
}

void main_process(Session *session)
{
	std::vector<char> 		msg_cipher;
	std::string				clear_msg;
	unsigned char 			*msg;
	App& 					app=App::Instance();
	session->aes = new Aes();
	key_exchange(session);
	if (login(session) == true)
	{
		app.logger->log("User logged", LOG_INFO);
		while (true)
		{
			if ((msg = getMessage(session)) == NULL)
				break;
			clear_msg = std::string(reinterpret_cast<char*>(msg));
			delete [] msg;
			if (manage_message(session, clear_msg) == -1)
				break;
		}
	}
	else
	{
		app.logger->log("Login failure", LOG_INFO);
	}
	delete session;
	app.logger->log("Client quit his connection", LOG_INFO);
	app.nb_client -= 1;
	return ;
}