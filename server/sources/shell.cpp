#include "../headers/shell.h"

    Shell::Shell()
    {
        execute();
    }

    Shell::~Shell()
    {
        int     status;
        close(infd[READ_END]);
        close(infd[WRITE_END]);
        close(outfd[READ_END]);
        close(outfd[WRITE_END]);
        close(errfd[READ_END]);
        close(errfd[WRITE_END]);
        waitpid(_pid, &status, WEXITED);
    }

    void Shell::execute()
    {
        auto rc = ::pipe(infd);
        if(rc < 0)
        {
            throw std::runtime_error(std::strerror(errno));
        }

        rc = ::pipe(outfd);
        if(rc < 0)
        {
            ::close(infd[READ_END]);
            ::close(infd[WRITE_END]);
            throw std::runtime_error(std::strerror(errno));
        }

        rc = ::pipe(errfd);
        if(rc < 0)
        {
            ::close(infd[READ_END]);
            ::close(infd[WRITE_END]);

            ::close(outfd[READ_END]);
            ::close(outfd[WRITE_END]);
            throw std::runtime_error(std::strerror(errno));
        }
        _pid = fork();
        if(_pid > 0) // PARENT
        {
            ::close(infd[READ_END]);    // Parent does not read from stdin
            ::close(outfd[WRITE_END]);  // Parent does not write to stdout
            ::close(errfd[WRITE_END]);  // Parent does not write to stderr
        }
        else if(_pid == 0) // CHILD
        {
            ::dup2(infd[READ_END], STDIN_FILENO);
            ::dup2(outfd[WRITE_END], STDOUT_FILENO);
            ::dup2(errfd[WRITE_END], STDERR_FILENO);


            ::close(infd[WRITE_END]);   // Child does not write to stdin
            ::close(outfd[READ_END]);   // Child does not read from stdout
            ::close(errfd[READ_END]);   // Child does not read from stderr
            // write(outfd[WRITE_END], "lol\n", 4);
            ::execl("/bin/bash", "bash", nullptr);
            // write(outfd[WRITE_END], "kol\n", 4);
        }

        // PARENT
        if(_pid < 0)
        {
            throw std::runtime_error("Failed to fork");
        }
    }