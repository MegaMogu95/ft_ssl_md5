NAME		= ft_ssl

CC			= cc
CFLAGS		= -Wall -Wextra -Werror -g
INCLUDES	= -Iincludes

SRCDIR		= srcs
OBJDIR		= objs

SRC			= main.c \
			  dispatch.c \
			  parse.c \
			  read_file.c \
			  run.c \
			  print.c \
			  utils.c \
			  md5.c \
			  sha256.c

OBJ			= $(addprefix $(OBJDIR)/, $(SRC:.c=.o))

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(OBJDIR)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
