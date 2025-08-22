#ifndef SNAPSHOT_H
#define SNAPSHOT_H

#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

#include "config.h"

/* Forward declarations */
typedef struct watch watch_t;

/* Single file/directory entry in a snapshot */
typedef struct entry {
	char *path;                            /* Relative path from snapshot root */
	kind_t type;                           /* ENTITY_FILE or ENTITY_DIRECTORY */
	size_t size;                           /* File size (0 for directories) */
	time_t mtime;                          /* Modification time */
	ino_t inode;                           /* Inode number for move detection */
} entry_t;

/* Complete snapshot of a directory tree at a point in time */
typedef struct snapshot {
	entry_t *entries;                      /* Array of entries, sorted by path */
	int count;                             /* Number of entries in snapshot */
	int capacity;                          /* Allocated capacity of entries array */
	char *root_path;                       /* Root directory path this snapshot represents */
} snapshot_t;

/* Difference between two snapshots */
typedef struct diff {
	/* Arrays of relative paths for each change type */
	char **created;                        /* Items that were created */
	char **deleted;                        /* Items that were deleted */
	char **renamed;                        /* Items that were renamed/moved */
	char **modified;                       /* Items that were modified */
	
	/* Counts for each change type */
	int created_count;                     /* Number of created items */
	int deleted_count;                     /* Number of deleted items */
	int renamed_count;                     /* Number of renamed items */
	int modified_count;                    /* Number of modified items */
	
	/* Summary information */
	int total_changes;                     /* Total number of changes */
	bool structural_changes;               /* True if directories were created/deleted */
} diff_t;

/* Core snapshot operations */
snapshot_t *snapshot_create(const char *root_path, const watch_t *watch);
void snapshot_destroy(snapshot_t *snapshot);

/* Snapshot comparison */
diff_t *snapshot_diff(const snapshot_t *baseline, const snapshot_t *current);
void diff_destroy(diff_t *diff);

/* Diff utility functions */
char *diff_list(const diff_t *diff, bool basename_only, const char *change_type);
diff_t *diff_copy(const diff_t *source);

/* Individual change type string lists for new placeholders */
char *diff_created(const diff_t *diff, bool basename_only);
char *diff_deleted(const diff_t *diff, bool basename_only);
char *diff_renamed(const diff_t *diff, bool basename_only);
char *diff_modified(const diff_t *diff, bool basename_only);
char *diff_changed(const diff_t *diff, bool basename_only);

#endif /* SNAPSHOT_H */
