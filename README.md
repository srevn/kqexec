# kqexec

A lightweight file and directory monitoring utility for FreeBSD and macOS that uses the Kqueue to watch for filesystem changes and execute custom commands in response to events.

## Features

- **Efficient Monitoring**: Uses Kqueue mechanism for low-overhead file system monitoring
- **Flexible Configuration**: Monitor specific files or entire directory trees
- **Event Filtering**: Select which event types to monitor (content, structure, metadata)
- **Custom Commands**: Execute arbitrary commands when events occur
- **Recursive Monitoring**: Automatically monitor new files and directories
- **Dynamic Directory Scanning**: Automatically detects and monitors new files and directories as they are created
- **Event-Driven Parent Watching**: Monitors non-existent paths by watching parent directories and promoting watches as path components are created
- **Glob Pattern Support**: Dynamic file and directory matching using wildcards (`*`, `?`, `[]`) with automatic watch promotion when patterns resolve
- **File and Directory Exclusion**: Flexible pattern-based exclusion of files and directories from monitoring using glob syntax
- **Hidden File Support**: Optional monitoring of hidden files and directories (starting with a dot)
- **Resource-Based Event Processing**: Tracks filesystem resources and their scanning profiles to detect meaningful changes
- **Command Cooldown**: Prevent command execution flooding when many events occur rapidly
- **Placeholder Substitution**: Dynamic command generation based on event details
- **Global Variables**: Reusable configuration variables with `${VARIABLE}` expansion and optional environment injection
- **Environment Variable Injection**: Event context provided to commands when enabled
- **Feedback Loop Prevention**: Filters out self-generated events and establishes a new baseline after command execution
- **Directory Stability Verification**: Uses `stat()` to recursively verify directory stability before executing commands
- **Configuration Hot-Reload**: Monitors the configuration file and automatically reloads when it changes
- **Control Interface**: Runtime control via Unix socket for enabling/disabling watches and querying status
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

Generate a sample configuration:

```sh
make config
```

Install the application and its configuration file:

```sh
make install
```

For an optimized release build:

```sh
make release
make install
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
- `-r, --cooldown=MS` : Set command cooldown time in milliseconds (default: 500)
- `-s, --socket-path=PATH` : Socket path for control interface (default: /tmp/kqexec.sock)
- `-h, --help` : Display help message

#### Control Commands

When running as a daemon, kqexec provides a control interface for runtime management:

- `--disable=WATCHES` : Temporarily disable specified watches (comma-separated names)
- `--enable=WATCHES` : Re-enable previously disabled watches (comma-separated names)  
- `--status` : Display current daemon and watch status
- `--list` : List all configured watches
- `--reload` : Reload configuration from file
- `--socket=PATH` : Socket path to connect to (default: /tmp/kqexec.sock)

Examples:
```sh
# Disable specific watches
kqexec --disable "Web Content,Log File"

# Enable specific disabled watches  
kqexec --enable "Web Content,Log File"

# Check daemon status
kqexec --status

# List all configured watches
kqexec --list

# Reload configuration
kqexec --reload
```

### Configuration File

The configuration file uses an INI-like format with sections for each watch entry:

```ini
[Section Name]
# Comments start with '#'
file = /path/to/file          # For monitoring a single file
directory = /path/to/dir      # For monitoring a directory
events = EVENT1,EVENT2        # Comma-separated list of events
enabled = true                # Whether the watch is initially enabled (default: true)
command = command to execute  # Command to run when events occur
environment = false           # Whether to set KQ_* environment variables (default: false)
processing_delay = 5000       # Delay in milliseconds before processing events (default: 0)
batch_timeout = 30000         # Batch events and process them when filesystem activity settles (default: 0)
complexity = 2.5              # System responsiveness with 0.1-5.0 range, higher = more cautious (default: 1.0)
log_output = false            # Whether to capture and log command output (default: false)
buffer_output = false         # Whether to buffer log output until command completes (default: false)
recursive = true              # For recursive directory monitoring (default: true)
hidden = false                # Whether to monitor hidden files/dirs (default: false)
exclude = *.tmp,build/*,.git  # Comma-separated patterns to exclude from monitoring
```

### Global Variables

Define reusable variables in a `[Variables]` section to reduce configuration duplication:

```ini
[Variables]
PROJECT_ROOT = /home/user/myproject
BUILD_SCRIPT = ${PROJECT_ROOT}/scripts/build.sh
ADMIN_EMAIL = admin@company.com

[Source Monitor]
directory = ${PROJECT_ROOT}/src
command = ${BUILD_SCRIPT} && echo "Build complete" | mail ${ADMIN_EMAIL}
environment = true  # Makes variables available as KQ_VAR_PROJECT_ROOT, etc.
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

Note: When monitoring directories, `kqueue` may not trigger structural change events if a file’s contents are modified in place. To work around this, set `events = STRUCTURE,CONTENT`, which will add each individual file in the directory to monitoring.

### Command Placeholders

Commands can include the following placeholders that will be replaced at runtime:

- `%created` : List of created items (newline-separated)
- `%deleted` : List of deleted items (newline-separated)
- `%renamed` : List of renamed items (format: old -> new, newline-separated)
- `%modified` : List of modified files (newline-separated)
- `%p` : Path where the event occurred
- `%n` : Filename (for files) or subdirectory name (for directories) which triggered the event
- `%d` : Directory containing the path that triggered the event
- `%b` : Base path of the watch from the config
- `%w` : Name of the watch from the config
- `%r` : Event path relative to the watch path
- `%l` : List of items (basenames) changed
- `%L` : List of items changed (newline-separated)
- `%s` : Size of the file in bytes (recursive for directories)
- `%S` : Human-readable size (e.g., 1.2M, 512K)
- `%t` : Time of the event (format: YYYY-MM-DD HH:MM:SS)
- `%u` : User who triggered the event
- `%e` : Event type which occurred

### Environment Variables

In addition to command placeholders, kqexec can optionally set environment variables that provide context about the event. To enable this feature, add `environment = true` (or `env_vars = true`) to your watch configuration:

- `KQ_EVENT_TYPE` : Event type (STRUCTURE, CONTENT, METADATA)
- `KQ_TRIGGER_PATH` : Full path where the event occurred
- `KQ_WATCH_NAME` : Name of the watch from the configuration
- `KQ_WATCH_PATH` : Base path being monitored
- `KQ_RELATIVE_PATH` : Event path relative to the watch base
- `KQ_TRIGGER_DIR` : Directory containing the file that triggered the event
- `KQ_USER_ID` : Numeric user ID that caused the event
- `KQ_USERNAME` : Username that caused the event (resolved from user ID)
- `KQ_TIMESTAMP` : ISO 8601 timestamp of the event
- `KQ_CHANGED` : Newline-separated list of all changes
- `KQ_CREATED` : Newline-separated list of items created
- `KQ_DELETED` : Newline-separated list of items deleted
- `KQ_RENAMED` : Newline-separated list of items renamed
- `KQ_MODIFIED` : Newline-separated list of items modified
- `KQ_VAR_*` : Global variables from `[Variables]` section (e.g., `KQ_VAR_PROJECT_ROOT`)

These environment variables make commands more powerful and reusable. For example:

```bash
#!/bin/bash
case "$KQ_EVENT_TYPE" in
    "STRUCTURE")
        echo "Directory structure changed in $KQ_WATCH_NAME"
        ;;
    "CONTENT")
        echo "File content modified: $KQ_RELATIVE_PATH"
        ;;
    *)
        echo "Event $KQ_EVENT_TYPE occurred on $KQ_RELATIVE_PATH"
        ;;
esac
```

## Examples

### Configuration

```ini
[Configuration Files]
# Monitor system configuration files
directory = /usr/local/etc
events = STRUCTURE,CONTENT
command = logger -p daemon.notice "Configuration changed in %p"
recursive = true
hidden = false

[Log File]
# Monitor a specific log file
file = /var/log/kqexec.log
events = CONTENT
command = echo "Log file %p was modified at %t by user %u (event: %e)" >> /var/log/kqexec_activity.log
processing_delay = 1000

[Web Content]
# Monitor web server content directory recursively
directory = /usr/local/www/data
events = STRUCTURE
command = /usr/local/bin/refresh_cache.sh %p %e
log_output = true
buffer_output = true
recursive = true
hidden = false

[Script Automation]
# Monitor directory and pass context via environment variables
directory = /home/user/projects
events = STRUCTURE
command = /home/user/scripts/build-deploy.sh
environment = true
log_output = true
recursive = true

[Git Operations]
# Monitor git repository with batch processing for multiple rapid changes
directory = /home/user/projects/myapp
events = STRUCTURE
command = /home/user/scripts/run-tests.sh
batch_timeout = 4000
log_output = true
buffer_output = true
recursive = true
exclude = .git/*,node_modules/*,*.tmp
```

### Common Use Cases

1. **Automatic deployment**: Monitor a git repository directory and trigger deployment when files change
2. **Configuration management**: Restart services when their configuration files are modified
3. **Security monitoring**: Log all changes to sensitive directories
4. **Backup verification**: Ensure backup jobs complete by monitoring the creation of expected files
5. **Hidden file monitoring**: Track changes in user configuration directories like .config
6. **Sync files or folders**: Keep mirror of documents in multiple locations with rsync
7. **Git workflow automation**: Use `batch_timeout` to handle git operations (clone, merge, checkout) that create many files rapidly
8. **Build system integration**: Use `processing_delay` for individual file changes and `batch_timeout` for bulk operations
9. **Runtime watch management**: Enable/disable watches based on system load or maintenance windows using the control interface

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

#### Runtime Control Interface

kqexec provides a Unix domain socket-based control interface for runtime management of watches. This allows you to:

- **Enable/Disable watches**: Temporarily turn watches on or off without restarting the daemon
- **Query status**: Check which watches are currently active or disabled  
- **List watches**: View all configured watches and their current state
- **Reload configuration**: Trigger a configuration reload without sending SIGHUP

**Watch State Management**: Watches can be configured to start in a disabled state using `enabled = false` in the configuration, then selectively enabled via the control interface as needed.

#### Command Cooldown

To prevent flooding when many events occur in rapid succession, kqexec implements a command cooldown mechanism. This rate limit applies per-watch, ensuring the same command won't be executed more frequently than the cooldown period while maintaining accurate baselines when changes occur.

Adjust the cooldown period with the `-r` option:

```sh
kqexec -r 10000  # Set cooldown period to 10000ms (10 seconds)
```

#### Hidden File Monitoring

kqexec can optionally monitor hidden files and directories (those starting with a dot). This is particularly useful for tracking user configuration files. Enable hidden file monitoring with the `include_hidden`/`hidden` option in the configuration:

#### Multiline Command Support

Commands can span multiple lines using backslash continuation or proper quoting, allowing for complex command structures and shell scripts.

#### Complexity-Based Responsiveness Control

The `complexity` option (range 0.1-5.0) provides fine-grained control over system responsiveness versus stability. Higher complexity values make the system more cautious and less responsive, while lower values prioritize speed:

- **Stability Verification**: More checks required before executing commands
- **Quiet Period Scaling**: Longer wait times before considering directories stable  
- **Backoff Behavior**: More aggressive delays during filesystem instability
- **Batch Processing**: Higher thresholds for detecting activity gaps
- **Depth/Size Sensitivity**: Complexity-scaled delays for deep or large directory structures
- **Temporary File Window**: Increseas period for what is considered temporary or in-progress operation

This allows tuning from very responsive (0.1) for simple workflows to highly cautious (5.0) for complex build systems or intensive I/O operations.

#### Delayed Event Processing

The `processing_delay`/`delay` option introduces an initial fixed delay before processing events, useful for scenarios where immediate response isn't required or for bursts of activity which need batching.

#### Batch Event Processing

The `batch_timeout`/`timeout` option defers events during active filesystem operations and processes them as a single operation when activity settles. Rather than a simple timer, it uses activity gap detection - the timeout window resets if events continue arriving, only triggering when there's been no activity for a complexity-determined threshold of the configured duration (by default 50%). This prevents command flooding during chaotic or intensive operations like indexing, builds, or large file transfers.

#### Buffered Command Output

When running commands, you have two options for handling their output: streaming it directly to logs as it is generated or buffering and flushing it once the command completes. Using `buffer_output` can be particularly helpful with verbose commands that produce extensive output.

#### File and Directory Exclusion

kqexec supports flexible file and directory exclusion patterns using the `exclude`/`ignore` configuration option. This feature allows you to prevent specific files or directories from triggering events, which is particularly useful for ignoring temporary files, build artifacts, or version control directories.

Exclusion patterns support glob syntax including:
- `*` : Matches any sequence of characters (except path separators)
- `?` : Matches any single character 
- `[abc]` : Matches any character in the set
- `**` : Matches any sequence including path separators (for recursive patterns)

Common exclusion examples:
```ini
exclude = *.tmp,*.log          # Exclude temporary and log files
exclude = node_modules/*       # Exclude Node.js dependencies
exclude = .git,.DS_Store       # Exclude version control and system files
exclude = build/**,dist/**     # Exclude build directories recursively
```

Exclusion filtering operates at multiple levels:
- **Discovery-time filtering**: Excluded directories are not monitored at all, reducing resource usage
- **Event-time filtering**: Excluded files within monitored directories don't trigger commands
- **Glob expansion filtering**: Excluded patterns are respected during dynamic watch creation

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
