#ifndef SNAPSHOT_H
#define SNAPSHOT_H

#include <stdbool.h>
#include <sys/types.h>

#include "config.h"

#define INITIAL_CAPACITY 64                /* Initial capacity for snapshot entries */

/* Single file/directory entry in a snapshot */
typedef struct entry {
	char *path;                            /* Relative path from snapshot root */
	kind_t type;                           /* ENTITY_FILE or ENTITY_DIRECTORY */
	size_t size;                           /* File size (0 for directories) */
	time_t mtime;                          /* Modification time */
	ino_t inode;                           /* Inode number for move detection */
} entry_t;

/* Hash table entry linking inode+type to snapshot entry */
typedef struct hash_entry {
	ino_t inode;                           /* File/directory inode number */
	kind_t type;                           /* ENTITY_FILE or ENTITY_DIRECTORY */
	entry_t *entry;                        /* Pointer to corresponding snapshot entry */
	struct hash_entry *next;               /* Next entry in collision chain */
} hash_entry_t;

/* Hash map for fast inode-based lookups */
typedef struct hash_map {
	hash_entry_t **buckets;                /* Array of bucket heads for chaining */
	size_t size;                           /* Number of buckets (should be prime) */
	size_t count;                          /* Number of entries stored */
} hash_map_t;

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

/* A read-only view of a list of paths from a diff */
typedef struct diff_list {
	int count;                             /* Number of paths in the array */
	const char *const *paths;              /* Pointer to the array of path strings */
} diff_list_t;

/* Core snapshot operations */
snapshot_t *snapshot_create(const char *root_path, const watch_t *watch);
void snapshot_destroy(snapshot_t *snapshot);

/* Snapshot comparison */
diff_t *snapshot_diff(const snapshot_t *baseline, const snapshot_t *current);
void diff_destroy(diff_t *diff);

/* Diff utility functions */
diff_t *diff_copy(const diff_t *source);
diff_list_t diff_list(const diff_t *diff, const char *change_type);

#endif /* SNAPSHOT_H */
