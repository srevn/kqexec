# Kqexec - File and Directory Monitor for FreeBSD and macOS

A lightweight file and directory monitoring utility for FreeBSD and macOS that uses the Kqueue to watch for filesystem changes and execute custom commands in response to events.

## Features

- **Efficient Monitoring**: Uses Kqueue mechanism for low-overhead file system monitoring
- **Flexible Configuration**: Monitor specific files or entire directory trees
- **Event Filtering**: Select which event types to monitor (create, modify, delete, etc.)
- **Custom Commands**: Execute arbitrary commands when events occur
- **Recursive Monitoring**: Automatically monitor new files and directories
- **Dynamic Directory Scanning**: Automatically detects and monitors new files and directories as they are created
- **Hidden File Support**: Optional monitoring of hidden files and directories (starting with a dot)
- **State-Based Event Processing**: Tracks the state of files and directories to detect meaningful changes
- **Command Debouncing**: Prevent command execution flooding when many events occur rapidly
- **Daemon Mode**: Run as a background service
- **Syslog Integration**: Comprehensive logging with configurable verbosity
- **Placeholder Substitution**: Dynamic command generation based on event details

## Requirements

- FreeBSD/macOS operating system
- Standard C compiler (cc)
- Make utility

## Installation

### Building from Source

1. Clone the repository or download the source code
2. Build the application:

```sh
make
```

### Installation Options

Install the application and its configuration file:

```sh
make install
```

Generate a sample configuration:

```sh
make config
```

## Usage

### Command Line Options

```
kqexec [options]
```

#### Options

- `-c, --config=FILE` : Configuration file (default: /usr/local/etc/kqexec.conf)
- `-d, --daemon` : Run as daemon
- `-l, --loglevel=LEVEL` : Set log level (0-7, default: 5)
- `-b, --debounce=MS` : Set command debounce time in milliseconds (default: 500)
- `-h, --help` : Display help message

### Configuration File

The configuration file uses an INI-like format with sections for each watch entry:

```ini
[Section Name]
# Comments start with '#'
file = /path/to/file         # For monitoring a single file
directory = /path/to/dir     # For monitoring a directory
events = EVENT1,EVENT2       # Comma-separated list of events
command = command to execute # Command to run when events occur
recursive = true             # For recursive directory monitoring (default: true)
hidden = false               # Whether to monitor hidden files/dirs (default: false)
```

### Event Types

Kqexec supports the following event types that can be specified in the configuration file:

- `CONTENT`: Monitors directory structure changes
  - Maps to NOTE_WRITE and NOTE_EXTEND in kqueue
  - Most effective for directories, not files
  - Triggers when a file's content is modified within a directory
  - Triggers for creation, deletion, and renaming operations within a directory
  - Example: When items are added to or removed from a directory

- `METADATA`: Monitors attribute changes for both files and directories
  - Maps to NOTE_ATTRIB and NOTE_LINK in kqueue
  - Works for both files and directories
  - Triggers when permissions, timestamps, or link counts change
  - Example: When `chmod` or `chown` is used on a file or directory

- `MODIFY`: Monitors changes to file contents
  - Maps to NOTE_DELETE, NOTE_RENAME, and NOTE_REVOKE in kqueue
  - Triggers when a file's content is modified
  - Example: When a text editor saves changes to a file

- `ALL`: Monitors all event types (combination of all the above)

### Command Placeholders

Commands can include the following placeholders that will be replaced at runtime:

- `%p` : Path where the event occurred
- `%t` : Time of the event (format: YYYY-MM-DD HH:MM:SS)
- `%u` : User who triggered the event
- `%e` : Event type

## Examples

### Basic Configuration

```ini
[Configuration Files]
# Monitor system configuration files
directory = /usr/local/etc
events = CONTENT
command = logger -p daemon.notice "Configuration changed in %p"
recursive = true
hidden = false

[Log File]
# Monitor a specific log file
file = /var/log/kqexec.log
events = MODIFY
command = echo "Log file %p was modified at %t by user %u (event: %e)" >> /var/log/kqexec_activity.log
```

### Advanced Configuration

```ini
[Web Content]
# Monitor web server content directory recursively
directory = /usr/local/www/data
events = CONTENT
command = /usr/local/bin/refresh_cache.sh %p %e
recursive = true
hidden = false

[SSL Certificates]
# Monitor certificate expiration
file = /etc/ssl/certs
events = MODIFY,CONTENT,METADATA
command = /usr/local/bin/cert_check.sh

[User Configuration]
# Monitor user config directories, including hidden files
directory = /home/user/.config
events = CONTENT
command = logger -p user.notice "User config changed: %p"
recursive = true
hidden = true

[Database Backups]
# Track changes to database backup directory
directory = /var/db/backups
events = ALL
command = mail -s "New database backup created: %p" admin@example.com
recursive = false
```

### Common Use Cases

1. **Automatic deployment**: Monitor a git repository directory and trigger deployment when files change
2. **Configuration management**: Restart services when their configuration files are modified
3. **Security monitoring**: Log all changes to sensitive directories
4. **Backup verification**: Ensure backup jobs complete by monitoring the creation of expected files
5. **Hidden file monitoring**: Track changes in user configuration directories like .config

## Running as a Service

### Setting Up the RC Script

Create an RC script in `/usr/local/etc/rc.d/kqexec`:

```sh
#!/bin/sh
#
# PROVIDE: kqexec
# REQUIRE: DAEMON
# KEYWORD: shutdown
#
# Add the following line to /etc/rc.conf to enable kqexec:
# kqexec_enable="YES"
#

. /etc/rc.subr

name=kqexec
rcvar=kqexec_enable

load_rc_config $name

: ${kqexec_enable:="NO"}
: ${kqexec_config:="/usr/local/etc/kqexec.conf"}

command="/usr/local/bin/kqexec"
command_args="-d -c ${kqexec_config}"

run_rc_command "$1"
```

Make the script executable:

```sh
chmod +x /usr/local/etc/rc.d/kqexec
```

### Enabling at Boot

Add the following line to `/etc/rc.conf`:

```sh
kqexec_enable="YES"
```

Start the service:

```sh
service kqexec start
```

## Advanced Features

### State-Based Event Processing

Kqexec uses an intelligent state tracking system to detect meaningful file system events. Rather than simply reacting to raw kqueue events, kqexec:

1. Tracks the state of each monitored file and directory
2. Compares new events against the known state
3. Determines the actual operation that occurred (create, modify, delete, etc.)
4. Filters events based on configured event types
5. Executes commands only when meaningful changes occur

This approach provides several advantages:
- Eliminates redundant command executions
- Properly identifies complex operations (like a file save that generates multiple raw events)
- Maintains context across related events
- Enables more precise filtering and control

### Dynamic Directory Scanning

When monitoring directories recursively, kqexec automatically detects changes in directory structure and updates its monitoring accordingly:

- New files and subdirectories are automatically added to monitoring
- Only previously unmonitored entries are added, preventing duplicate watches
- Directory scanning is debounced to prevent excessive resource usage during rapid changes
- Can optionally include hidden files and directories in monitoring

### Command Debouncing

To prevent flooding when many events occur in rapid succession, kqexec implements command debouncing based on entity state. This ensures the same command won't be executed more frequently than the debounce period.

Adjust the debounce period with the `-b` option:

```sh
kqexec -b 1000  # Set debounce period to 1000ms (1 second)
```

Different operations can have different debounce periods based on their importance:
- Critical operations like file creation/deletion use shorter debounce times
- Less critical operations like attribute changes use the full debounce time

### Hidden File Monitoring

Kqexec can optionally monitor hidden files and directories (those starting with a dot). This is particularly useful for tracking user configuration files.

Enable hidden file monitoring with the `hidden` or `include_hidden` option in the configuration:

```ini
[User Configs]
directory = /home/user/.config
events = MODIFY,CREATE
command = logger "Config changed: %p"
recursive = true
hidden = true
```

## Troubleshooting

### Common Issues

1. **"Failed to open file/directory"**: Ensure the user running kqexec has appropriate permissions
2. **"Failed to create kqueue"**: Check system limits for open file descriptors
3. **Missing events**: Check if the path is hidden and the `hidden` option is set to `true`

### Viewing Logs

Check syslog for messages from kqexec:

```sh
grep kqexec /var/log/messages
```

Increase log verbosity for debugging:

```sh
kqexec -l 7  # Set log level to DEBUG
```
