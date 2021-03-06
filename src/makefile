CC=gcc
CFLAGS=-O3 -std=c99
TARGET=wiqacrypt
all: $(TARGET)

$(TARGET): wiqacrypt.c
	$(CC) wiqacrypt.c $(CFLAGS) -o $(TARGET)

clean:
	$(RM) $(TARGET)
