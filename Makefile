# Detect operating system
UNAME_S := $(shell uname -s)

# Compiler and flags
CC = cc
CFLAGS = -Wall -Wextra -std=c11 -pedantic -g
LDFLAGS = -lm

# OS-specific settings
ifeq ($(UNAME_S),FreeBSD)
	CFLAGS += -DIS_FREEBSD
	INSTALL_PREFIX = /usr/local
else ifeq ($(UNAME_S),Darwin)
	CFLAGS += -DIS_MACOS
	INSTALL_PREFIX = /usr/local
else
	$(error Unsupported operating system: $(UNAME_S))
endif

# Source files
SRCS = src/main.c \
	   src/config.c \
	   src/monitor.c \
	   src/command.c \
	   src/states.c \
	   src/daemon.c \
	   src/log.c

# Object files
OBJS = $(SRCS:.c=.o)

# Binary name
TARGET = kqexec

# Default target
all: $(TARGET)

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Link object files
$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $(TARGET)

# Clean up
clean:
	rm -f $(OBJS) $(TARGET)

# Install
install: $(TARGET)
	install -s $(TARGET) $(INSTALL_PREFIX)/bin/
	mkdir -p $(INSTALL_PREFIX)/etc
	[ -f $(INSTALL_PREFIX)/etc/kqexec.conf ] || \
		install -m 644 kqexec.conf.sample $(INSTALL_PREFIX)/etc/kqexec.conf
	
ifeq ($(UNAME_S),FreeBSD)
	mkdir -p $(INSTALL_PREFIX)/etc/rc.d
	install -m 755 etc/kqexec.rc $(INSTALL_PREFIX)/etc/rc.d/kqexec
else ifeq ($(UNAME_S),Darwin)
	mkdir -p $(INSTALL_PREFIX)/etc/kqexec
	install -m 644 etc/com.kqexec.daemon.plist $(INSTALL_PREFIX)/etc/kqexec/com.kqexec.daemon.plist
endif

# Create sample configuration
kqexec.conf.sample:
	@echo "[Configuration]" > $@
	@echo "" >> $@
	@echo "# Monitor system config files" >> $@
	@echo "directory = /usr/local/etc" >> $@
	@echo "events = MODIFY" >> $@
	@echo "command = logger -p daemon.notice \"Configuration changed in %p\"" >> $@
	@echo "recursive = true" >> $@
	@echo "hidden = false" >> $@
	@echo "" >> $@
	@echo "[Log File]" >> $@
	@echo "" >> $@
	@echo "# Monitor file" >> $@
	@echo "file = /var/log/kqexec.log" >> $@
	@echo "events = MODIFY" >> $@
	@echo "command = echo \"Log file %p was modified at %t by user %u (event: %e)\" >> /var/log/kqexec_activity.log" >> $@
	@echo "" >> $@
	@echo "[User Config]" >> $@
	@echo "" >> $@
	@echo "# Monitor user configuration directory including hidden files" >> $@
	@echo "directory = /home/user/.config" >> $@
	@echo "events = MODIFY,CREATE,DELETE" >> $@
	@echo "command = logger -p user.notice \"User configuration changed in %p\"" >> $@
	@echo "recursive = true" >> $@
	@echo "hidden = true" >> $@

# Generate sample configuration
config: kqexec.conf.sample

# Phony targets
.PHONY: all clean install config