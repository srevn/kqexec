# Detect operating system
UNAME_S := $(shell uname -s)

# Compiler and flags
CC = cc
CFLAGS = -Wall -Wextra -o2 -std=c11 -pedantic -g
LDFLAGS = -lm -lpthread -flto

# Debug build with sanitizers
ifdef DEBUG
    CC = clang
    CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer -O1
    LDFLAGS += -fsanitize=address,undefined
endif

# Release build with symbol stripping
ifdef RELEASE
    CFLAGS = -Wall -Wextra -std=c11 -o2 -DNDEBUG -march=native -mtune=native \
             -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE \
             -fdata-sections -ffunction-sections -flto
    ifeq ($(UNAME_S),Darwin)
        LDFLAGS = -lm -lpthread -Wl,-dead_strip -flto
    else ifeq ($(UNAME_S),FreeBSD)
        LDFLAGS = -lm -lpthread -pie -Wl,--gc-sections -Wl,-z,relro,-z,now -flto
    endif
endif

# OS-specific settings
ifeq ($(UNAME_S),FreeBSD)
	CFLAGS += -DIS_FREEBSD
	INSTALL_PREFIX = /usr/local
	CONFIG_DIR = $(INSTALL_PREFIX)/etc
	LAUNCHD_DIR = $(INSTALL_PREFIX)/etc/rc.d
else ifeq ($(UNAME_S),Darwin)
	CFLAGS += -DIS_MACOS
	INSTALL_PREFIX = /usr/local
	CONFIG_DIR = $(HOME)/.config/kqexec
	LAUNCHD_DIR = $(HOME)/Library/LaunchAgents
	# Installation paths for plist
	KQEXEC_BIN = $(INSTALL_PREFIX)/bin/kqexec
	KQEXEC_CONF = $(CONFIG_DIR)/kqexec.conf
	KQEXEC_LOG = $(HOME)/Library/Logs/kqexec.log
else
	$(error Unsupported operating system: $(UNAME_S))
endif

# Source files
SRCS = src/main.c \
	   src/queue.c \
	   src/events.c \
	   src/config.c \
	   src/mapper.c \
	   src/monitor.c \
	   src/tracker.c \
	   src/pending.c \
	   src/scanner.c \
	   src/registry.c \
	   src/resource.c \
	   src/stability.c \
	   src/utilities.c \
	   src/snapshot.c \
	   src/command.c \
	   src/threads.c \
	   src/daemon.c \
	   src/logger.c

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
	@if [ -n "$(RELEASE)" ]; then \
		strip $(TARGET); \
	fi

# Clean up
clean:
	rm -f $(OBJS) $(TARGET)

# Install
install: $(TARGET)
	@echo "Installing application to $(INSTALL_PREFIX)/bin/$(TARGET)"
	@install -s $(TARGET) $(INSTALL_PREFIX)/bin/
	
ifeq ($(UNAME_S),FreeBSD)
	@echo "Installing script service file to $(LAUNCHD_DIR)/kqexec"
	@mkdir -p $(LAUNCHD_DIR)
	
	@install -m 755 etc/kqexec.rc $(LAUNCHD_DIR)/kqexec
	@echo "Installing configuration file sample to $(CONFIG_DIR)/kqexec.conf"
	@mkdir -p $(CONFIG_DIR)
	@[ -f $(CONFIG_DIR)/kqexec.conf ] || \
		install -m 644 kqexec.conf.sample $(CONFIG_DIR)/kqexec.conf
	
else ifeq ($(UNAME_S),Darwin)
	@echo "Installing configuration file sample to $(CONFIG_DIR)/kqexec.conf"
	@mkdir -p $(CONFIG_DIR)
	@[ -f $(CONFIG_DIR)/kqexec.conf ] || \
		install -m 644 kqexec.conf.sample $(CONFIG_DIR)/kqexec.conf
	
	@echo "Generating daemon plist from template"
	@sed -e 's|@KQEXEC_BIN@|$(KQEXEC_BIN)|g' \
		-e 's|@KQEXEC_CONF@|$(KQEXEC_CONF)|g' \
		-e 's|@KQEXEC_LOG@|$(KQEXEC_LOG)|g' \
		etc/com.kqexec.daemon.plist > etc/com.kqexec.daemon.plist.sample
	
	@if [ -n "$(LAUNCHD_DIR)" ]; then \
		echo "Installing launchd plist to $(LAUNCHD_DIR)"; \
		mkdir -p $(LAUNCHD_DIR); \
		install -m 644 etc/com.kqexec.daemon.plist.sample $(LAUNCHD_DIR)/com.kqexec.daemon.plist; \
		rm -f etc/com.kqexec.daemon.plist.sample; \
		echo "Installed: $(LAUNCHD_DIR)/com.kqexec.daemon.plist"; \
		echo "To load the daemon now, run:"; \
		echo "launchctl bootstrap gui/`id -u` $(LAUNCHD_DIR)/com.kqexec.daemon.plist"; \
	else \
		echo "LAUNCHD_DIR not set, skipping launchd installation"; \
	fi
endif

# Uninstall target
uninstall:
	@echo "Removing application from $(INSTALL_PREFIX)/bin"
	@rm -f $(INSTALL_PREFIX)/bin/$(TARGET)
	
ifeq ($(UNAME_S),FreeBSD)
	@rm -f $(LAUNCHD_DIR)/kqexec
	@echo "Configuration files not removed. To completely remove, execute:"
	@echo "  rm -f $(CONFIG_DIR)/kqexec.conf"
	
else ifeq ($(UNAME_S),Darwin)
	@if [ -n "$(LAUNCHD_DIR)" ]; then \
		echo "Unloading and removing launchd plist from $(LAUNCHD_DIR)"; \
		launchctl bootout gui/`id -u` $(LAUNCHD_DIR)/com.kqexec.daemon.plist 2>/dev/null || true; \
		rm -f $(LAUNCHD_DIR)/com.kqexec.daemon.plist; \
	fi
	
	@echo "Configuration files not removed. To completely remove, execute:"
	@echo "  rm -f $(CONFIG_DIR)/kqexec.conf"
endif

# Create sample configuration
kqexec.conf.sample:
	@echo "[Configuration]" > $@
	@echo "# Monitor system config files" >> $@
	@echo "directory = /usr/local/etc" >> $@
	@echo "events = STRUCTURE" >> $@
	@echo "command = logger -p daemon.notice \"Configuration changed in %p\"" >> $@
	@echo "log_output = false" >> $@
	@echo "complexity = 0.7" >> $@
	@echo "buffer_output = false" >> $@
	@echo "recursive = true" >> $@
	@echo "hidden = false" >> $@
	@echo "" >> $@
	@echo "[Log File]" >> $@
	@echo "# Monitor file" >> $@
	@echo "file = /var/log/kqexec.log" >> $@
	@echo "events = CONTENT" >> $@
	@echo "command = echo \"Log file %p was modified at %t by user %u (event: %e)\" >> /var/log/kqexec_activity.log" >> $@
	@echo "log_output = true" >> $@
	@echo "processing_delay = 100" >> $@
	@echo "" >> $@
	@echo "[User Config]" >> $@
	@echo "# Monitor user configuration directory including hidden files" >> $@
ifeq ($(UNAME_S),Darwin)
	@echo "directory = $(HOME)/Library/Preferences" >> $@
else
	@echo "directory = /home/user/.config" >> $@
endif
	@echo "events = STRUCTURE,CONTENT,METADATA" >> $@
	@echo "command = logger -p user.notice \"User configuration changed in %p\"" >> $@
	@echo "recursive = true" >> $@
	@echo "hidden = true" >> $@
	@echo "" >> $@
	@echo "[Script Automation]" >> $@
	@echo "# Monitor directory and pass context via environment variables" >> $@
ifeq ($(UNAME_S),Darwin)
	@echo "directory = $(HOME)/projects" >> $@
	@echo "command = $(HOME)/scripts/build-deploy.sh" >> $@
else
	@echo "directory = /home/user/projects" >> $@
	@echo "command = /home/user/scripts/build-deploy.sh" >> $@
endif
	@echo "events = STRUCTURE,CONTENT" >> $@
	@echo "batch_timeout = 15000" >> $@
	@echo "environment = true" >> $@
	@echo "log_output = true" >> $@
	@echo "recursive = true" >> $@

# Generate sample configuration
config: kqexec.conf.sample

# Debug target
debug: clean
	$(MAKE) DEBUG=1

# Release target
release: clean
	$(MAKE) RELEASE=1

# Phony targets
.PHONY: all clean install uninstall config debug release
