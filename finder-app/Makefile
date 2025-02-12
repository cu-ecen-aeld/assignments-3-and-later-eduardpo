# Compiler and flags
CROSS_COMPILE ?= aarch64-none-linux-gnu-
#CC := $(CROSS_COMPILE)gcc
CC = gcc
CFLAGS = -Wall -std=c99

# Output executable
TARGET = writer

# Source files
SRC = writer.c

# Object files
OBJ = $(SRC:.c=.o)

# Compile the program
$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET)

# Compile the source file into an object file
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up the object and executable files
clean:
	rm -f $(OBJ) $(TARGET)

