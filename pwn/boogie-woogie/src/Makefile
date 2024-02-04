# makefile that takes main.c and produces boogie-woogie

CC = gcc
CFLAGS = -Wall -Werror -Wextra -pedantic -std=c99 -g
SRC = main.c
OBJ = $(SRC:.c=.o)
TARGET = boogie-woogie

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET)

clean:
	rm -f $(OBJ) $(TARGET)

re: clean all

.PHONY: all clean re

