# C OSS Compliance Test Project Makefile
# Pure C language project (not C++)

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -pedantic
LDFLAGS = -lssl -lcrypto -lcurl -lz -lpthread -ljson-c

SRCDIR = src
INCDIR = include
OBJDIR = obj
TARGET = c-oss-test

SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# System dependencies (C libraries)
# - OpenSSL (libssl, libcrypto)
# - libcurl  
# - zlib
# - json-c (C JSON library, not C++)
# - pthread

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJECTS)
	@echo "Linking $(TARGET)..."
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(OBJDIR) $(TARGET)

install: $(TARGET)
	install -D $(TARGET) /usr/local/bin/$(TARGET)

# Dependencies check
deps-check:
	@echo "Checking C library dependencies..."
	@pkg-config --exists openssl || echo "Warning: OpenSSL development packages not found"
	@pkg-config --exists libcurl || echo "Warning: libcurl development packages not found"
	@pkg-config --exists zlib || echo "Warning: zlib development packages not found"
	@pkg-config --exists json-c || echo "Warning: json-c development packages not found"

# For Ubuntu/Debian systems
deps-install-apt:
	sudo apt-get update
	sudo apt-get install -y libssl-dev libcurl4-openssl-dev zlib1g-dev libjson-c-dev

# For CentOS/RHEL systems  
deps-install-yum:
	sudo yum install -y openssl-devel libcurl-devel zlib-devel json-c-devel

# For macOS with Homebrew
deps-install-brew:
	brew install openssl curl zlib json-c 