CXX=g++ -std=c++17 -Wall -Wextra -Werror
CLI_SRC=client/sources/
# 

NAME_SERVER = Matt_daemon
NAME_CLIENT = Ben_AFK

SRCS_CLIENT =	./client/sources/main.cpp \
				./client/sources/client.cpp \
				./common/sources/socket.cpp \
				./common/sources/rsa.cpp \
				./common/sources/aes.cpp

SRC_SERVER = 	./server/sources/main.cpp \
				./server/sources/server.cpp \
				./server/sources/app.cpp \
				./server/sources/session.cpp \
				./server/sources/shell.cpp \
				./server/sources/Tintin_reporter.cpp \
				./common/sources/rsa.cpp \
				./common/sources/socket.cpp \
				./common/sources/aes.cpp

OBJ_CLIENT = $(SRCS_CLIENT:.cpp=.o)
OBJ_SERVER = $(SRC_SERVER:.cpp=.o)

all: $(NAME_CLIENT) $(NAME_SERVER)

client: $(NAME_CLIENT)

server: $(NAME_SERVER)

$(NAME_CLIENT): $(OBJ_CLIENT)
	$(CXX) $(OBJ_CLIENT) -o $(NAME_CLIENT) -I ./client/headers/ -I ./common/headers/ -lstdc++ -L /usr/local/ssl/lib -lssl -lcrypto
	@echo "\033[36m◉ \033[33mmake client is done\033[0m"

$(NAME_SERVER): $(OBJ_SERVER)
	$(CXX) $(OBJ_SERVER) -o $(NAME_SERVER) -I ./server/headers/ -I ./common/headers/ -lstdc++ -L /usr/local/ssl/lib -lssl -lcrypto -pthread
	@echo "\033[36m◉ \033[33mmake server is done\033[0m"

clean:
	rm -f $(OBJ_CLIENT)
	rm -f $(OBJ_SERVER)
	@echo "\033[36m◉ \033[33mclean done\033[0m"

fclean: clean
	rm -f $(NAME_CLIENT)
	rm -f $(NAME_SERVER)
	@echo "\033[36m◉ \033[33mfclean done\033[0m"

re: fclean all

.PHONY: clean fclean re
