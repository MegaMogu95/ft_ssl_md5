NAME		= ft_ssl

CC			= cc
CFLAGS		= -Wall -Wextra -Werror -g
INCLUDES	= -Iincludes

SRCDIR		= srcs
OBJDIR		= objs

SRC			= main.c \
			  dispatch.c \
			  utils.c \
			  digest/run_digest.c \
			  digest/parse_digest.c \
			  digest/read_file.c \
			  digest/print.c \
			  digest/md5.c \
			  digest/sha256.c \
			  cipher/run_cipher.c \
			  cipher/base64.c \
			  cipher/des_ecb.c \
			  cipher/des_cbc.c

OBJ			= $(addprefix $(OBJDIR)/, $(SRC:.c=.o))

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(OBJDIR)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
