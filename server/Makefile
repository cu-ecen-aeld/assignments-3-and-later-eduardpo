SRC := aesdsocket.c
TARGET := aesdsocket
OBJS := $(SRC:.c=.o)

# Comment out for native
#CROSS_COMPILE := aarch64-none-linux-gnu-

#CC := $(CROSS_COMPILE)gcc
CFLAGS = -Wall -Werror -I/usr/local/include

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET)

$(OBJS): $(SRC)
	$(CC) $(CFLAGS) -c $(SRC) -o $(OBJS)

clean:
	rm -f $(OBJS) $(TARGET)

