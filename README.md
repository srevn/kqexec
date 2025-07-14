# kqexec

A lightweight file and directory monitoring utility for FreeBSD and macOS that uses the Kqueue to watch for filesystem changes and execute custom commands in response to events.

## Features

- **Efficient Monitoring**: Uses Kqueue mechanism for low-overhead file system monitoring
- **Flexible Configuration**: Monitor specific files or entire directory trees
- **Event Filtering**: Select which event types to monitor (content, structure, metadata)
- **Custom Commands**: Execute arbitrary commands when events occur
- **Recursive Monitoring**: Automatically monitor new files and directories
- **Dynamic Directory Scanning**: Automatically detects and monitors new files and directories as they are created
- **Hidden File Support**: Optional monitoring of hidden files and directories (starting with a dot)
- **State-Based Event Processing**: Tracks the state of files and directories to detect meaningful changes
- **Command Debouncing**: Prevent command execution flooding when many events occur rapidly
- **Placeholder Substitution**: Dynamic command generation based on event details
- **Command Intent Tracking**: Filters out self-generated events by analyzing command operations
- **Directory Stability Verification**: Uses `stat()` to recursively verify directory stability before executing commands
- **Configuration Hot-Reload**: Monitors the configuration file and automatically reloads when it changes
- **Syslog Integration**: Comprehensive logging with configurable verbosity
- **Daemon Mode**: Run as a background service

## Requirements

- FreeBSD/macOS operating system
- Standard C compiler (cc)
- Make utility (preferably GNU Make)

## Installation

#### Building from Source
1. Clone the repository or download the source code
2. Build the application:

```sh
make
```

#### Installation Options

Install the application and its configuration file:

```sh
make install
```

Generate a sample configuration:

```sh
make config
```

**Note:** Due to incompatibilities between macOS and FreeBSD Make utility, it's best to use gmake on FreeBSD.

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
file = /path/to/file          # For monitoring a single file
directory = /path/to/dir      # For monitoring a directory
events = EVENT1,EVENT2        # Comma-separated list of events
command = command to execute  # Command to run when events occur
processing_delay = 5000       # Delay in milliseconds before processing events (default: 0)
complexity = 2.5              # Higher values reduce I/O by waiting longer for stability checks. (default: 1.0)
log_output = false            # Whether to capture and log command output (default: false)
buffer_output = false         # Whether to buffer log output until command completes (default: false)
recursive = true              # For recursive directory monitoring (default: true)
hidden = false                # Whether to monitor hidden files/dirs (default: false)
```

### Event Types

Kqexec supports the following event types that can be specified in the configuration file:

- `STRUCTURE`: Monitors directory structure changes
  - Maps to `NOTE_WRITE` and `NOTE_EXTEND` in kqueue
  - Most effective for directories, not files
  - Triggers when a file's content is modified within a directory
  - Triggers for creation, deletion, and renaming operations within a directory
  - Example: When items are added to or removed from a directory

- `METADATA`: Monitors attribute changes for both files and directories
  - Maps to `NOTE_ATTRIB` and `NOTE_LINK` in kqueue
  - Works for both files and directories
  - Triggers when permissions, timestamps, or link counts change
  - Example: When `chmod` or `chown` is used on a file or directory

- `CONTENT`: Monitors changes to file contents
  - Maps to `NOTE_DELETE`, `NOTE_RENAME`, `NOTE_REVOKE`, and `NOTE_WRITE` in kqueue
  - Triggers when a file's content is modified
  - Covers both atomic saves (modern editors) and in-place edits (nano, vi)
  - Example: When a text editor saves changes to a file

- `ALL`: Monitors all event types (combination of all the above)

### Command Placeholders

Commands can include the following placeholders that will be replaced at runtime:

- `%p` : Path where the event occurred
- `%n` : Filename (for files) or subdirectory name (for directories) which triggered the event
- `%d` : Directory containing the path that triggered the event
- `%b` : Base path of the watch from the config
- `%w` : Name of the watch from the config
- `%r` : Event path relative to the watch path
- `%f` : The file that triggered a directory event (most recent)
- `%F` : The basename of the file that triggered a directory event
- `%l` : List of filenames (without paths) modified within 1 second of current event
- `%L` : List of files modified within 1 second of current event (newline-separated)
- `%s` : Size of the file in bytes (recursive for directories)
- `%S` : Human-readable size (e.g., 1.2M, 512K)
- `%t` : Time of the event (format: YYYY-MM-DD HH:MM:SS)
- `%u` : User who triggered the event
- `%e` : Event type which occurred

## Examples

### Basic Configuration

```ini
[Configuration Files]
# Monitor system configuration files
directory = /usr/local/etc
events = STRUCTURE,METADATA
command = logger -p daemon.notice "Configuration changed in %p"
recursive = true
hidden = false

[Log File]
# Monitor a specific log file
file = /var/log/kqexec.log
events = CONTENT
command = echo "Log file %p was modified at %t by user %u (event: %e)" >> /var/log/kqexec_activity.log
```

### Advanced Configuration

```ini
[Web Content]
# Monitor web server content directory recursively
directory = /usr/local/www/data
events = STRUCTURE
command = /usr/local/bin/refresh_cache.sh %p %e
log_output = true
buffer_output = true
recursive = true
hidden = false

[SSL Certificates]
# Monitor certificate expiration
file = /etc/ssl/certs
events = CONTENT,STRUCTURE,METADATA
command = /usr/local/bin/cert_check.sh

[User Configuration]
# Monitor user config directories, including hidden files
directory = /home/user/.config
events = STRUCTURE
command = logger -p user.notice "User config changed: %p"
recursive = true
hidden = true

[Database Backups]
# Track changes to database backup directory
directory = /var/db/backups
events = ALL
command = mail -s "New database backup created: %p" admin@example.com
processing_delay = 10000
log_output = false
recursive = false
```

### Common Use Cases

1. **Automatic deployment**: Monitor a git repository directory and trigger deployment when files change
2. **Configuration management**: Restart services when their configuration files are modified
3. **Security monitoring**: Log all changes to sensitive directories
4. **Backup verification**: Ensure backup jobs complete by monitoring the creation of expected files
5. **Hidden file monitoring**: Track changes in user configuration directories like .config
5. **Sync files or folders:**: Keep mirror of documents in multiple locations with rsync

## Running as a Service

### launchd on macOS

To load or unload the daemon:

```sh
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.kqexec.daemon.plist # to load
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.kqexec.daemon.plist # to unload
```

### RC Script on FreeBSD

To enable at boot add the following line to `/etc/rc.conf`:

```sh
kqexec_enable="YES"
```

Start the service:

```sh
service kqexec start
```

**Note:** `make install` automatically installs launchd agent or rc script based on your distribution.

## Reloading Configuration

kqexec accepts SIGHUP signal for reloading configuration without restarting the application.

On FreeBSD you can run:

```sh
service kqexec reload
```

Or, on macOS:

```sh
launchctl kill SIGHUP gui/$(id -u)/com.kqexec.daemon
```

**Note:** kqexec automatically monitors changes to its configuration file and reloads when modified.

## Advanced Features

#### Command Debouncing

To prevent flooding when many events occur in rapid succession, kqexec implements command debouncing based on entity state. This ensures the same command won't be executed more frequently than the debounce period.

Adjust the debounce period with the `-b` option:

```sh
kqexec -b 1000  # Set debounce period to 1000ms (1 second)
```

Different operations can have different debounce periods based on their importance:
- Critical operations like file creation/deletion use shorter debounce times
- Less critical operations like attribute changes use the full debounce time

#### Hidden File Monitoring

kqexec can optionally monitor hidden files and directories (those starting with a dot). This is particularly useful for tracking user configuration files. Enable hidden file monitoring with the `include_hidden`/`hidden` option in the configuration:

#### Multiline Command Support

Commands can span multiple lines using backslash continuation or proper quoting, allowing for complex command structures and shell scripts.

#### Complexity-Based Stability Control

The `complexity` option allows fine-tuning of stability verification for heavy filesystem operations. Higher values increase wait times for stability checks, reducing I/O overhead during intensive operations.

#### Delayed Event Processing

The `processing_delay`/`delay` option introduces an initial delay before processing events, useful for scenarios where immediate response isn't required or when batching operations.

#### Buffered Command Output

When running commands, you have two options for handling their output: streaming it directly to logs as it is generated or buffering and flushing it once the command completes. Using `buffer_output` can be particularly helpful with verbose commands that produce extensive output.

## Viewing Logs

On FreeBSD, check syslog for messages from kqexec:

```sh
grep kqexec /var/log/messages
```

If you prefer separate log file, add this lines to `/etc/syslog.conf`

```ini
!kqexec
*.*              /var/log/kqexec.log
```

**Note:** You can add a second-pass filter by changing to `*.notice` or `*.info` if log level is set higher.

On macOS:

```sh
tail -n 50 ~/Library/Logs/kqexec.log
```
