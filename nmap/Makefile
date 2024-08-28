SRC	=	$(addsuffix .c,		\
		$(addprefix src/,	\
			main			\
			options			\
			scans			\
			sender			\
			parsing			\
			utils			\
			setup			\
			scanner			\
			listener		\
			threads			\
			packet_handler	\
			filter			\
			routine			\
			show_results	\
			interpreters	\
		))

NAME	= ft_nmap

SHELL	= /bin/zsh

OBJ		= ${SRC:src/%.c=.obj/%.o}

CC		= gcc

LIBFT	= libft/libft.a

INCLUDE = -Iinclude/ -Ilibft/include

CFLAGS	=  -Wall -Werror -Wextra -lpcap -lpthread -pipe ${INCLUDE} -O3 -g3 #-fsanitize=address

all: __watermark ${LIBFT} ${NAME}


${LIBFT}:
	@if [[ -f ${LIBFT} ]] ;	\
		then; \
			echo "libft already compiled"; \
		else; \
			echo "Compiling libft"; \
			make --silent -C libft >/dev/null; \
			echo "${LIBFT} compiled"; \
	fi;


.obj/%.o: src/%.c
	@${CC} ${CFLAGS} -c $< -o ${<:src/%.c=.obj/%.o}


${NAME}: ${OBJ}
	@echo "Compiling ${NAME}"
	@${CC} ${OBJ} ${LIBFT} ${CFLAGS} -o ${NAME}
	@echo "${NAME} compiled"


__watermark:
	@echo -e "\033[42m __   ____  _____  _____      \033[0m"
	@echo -e "\033[42m \\ \\ |    \\ \\___ \\ \\___ \\     \033[0m"
	@echo -e "\033[42m  \\ \\ \\ |\\ \\   _\\ \\   _\\ \\    \033[0m"
	@echo -e "\033[42m   \\ \\ \\ \\\\\\ \\  \\__ \\  \\__ \\   \033[0m"
	@echo -e "\033[42m    \\ \\ \\ \\| \\  __\\ \\  __\\ \\  \033[0m"
	@echo -e "\033[42m     \\_\\ \\____| \\____\\ \\____\\ \033[0m"
	@echo -e "\033[42m                              \033[0m\n"


decoder:
	@${CC} ${CFLAGS} -o decoder src/decoder.c


clean:
	@make --silent -C libft clean >/dev/null
	@rm -rf ${OBJ}


fclean:
	@make --silent -C libft fclean >/dev/null
	@rm -rf ${OBJ} ${NAME}


__re_fclean:
	@make --silent -C libft clean >/dev/null
	@rm -rf ${OBJ} ${NAME}


re: __re_fclean all


.PHONY: all __watermark ${LIBFT} clean flcean __re_fclean re
