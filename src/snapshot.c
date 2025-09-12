#include "snapshot.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "logger.h"

/* Calculate next prime number >= n for better hash distribution */
static size_t next_prime(size_t n) {
	if (n < 2) return 2;
	if (n == 2) return 2;
	if (n % 2 == 0) n++;

	while (1) {
		bool is_prime = true;
		for (size_t i = 3; i * i <= n; i += 2) {
			if (n % i == 0) {
				is_prime = false;
				break;
			}
		}
		if (is_prime) return n;
		n += 2;
	}
}

/* Hash function for inode + type combination */
static size_t hash_inode(ino_t inode, kind_t type, size_t bucket_count) {
	/* Simple hash combining inode and type */
	size_t hash = (size_t) inode ^ ((size_t) type << 16);
	return hash % bucket_count;
}

/* Create a hash map with specified number of buckets */
static hash_map_t *map_create(size_t bucket_count) {
	hash_map_t *map = calloc(1, sizeof(hash_map_t));
	if (!map) return NULL;

	map->buckets = calloc(bucket_count, sizeof(hash_entry_t *));
	if (!map->buckets) {
		free(map);
		return NULL;
	}

	map->size = bucket_count;
	map->count = 0;
	return map;
}

/* Destroy a hash map and all its entries */
static void map_destroy(hash_map_t *map) {
	if (!map) return;

	for (size_t i = 0; i < map->size; i++) {
		hash_entry_t *entry = map->buckets[i];
		while (entry) {
			hash_entry_t *next = entry->next;
			free(entry);
			entry = next;
		}
	}

	free(map->buckets);
	free(map);
}

/* Insert an entry into the hash map */
static bool map_insert(hash_map_t *map, entry_t *entry) {
	if (!map || !entry) return false;

	size_t index = hash_inode(entry->inode, entry->type, map->size);

	hash_entry_t *hash_entry = malloc(sizeof(hash_entry_t));
	if (!hash_entry) return false;

	hash_entry->inode = entry->inode;
	hash_entry->type = entry->type;
	hash_entry->entry = entry;
	hash_entry->next = map->buckets[index];

	map->buckets[index] = hash_entry;
	map->count++;
	return true;
}

/* Lookup an entry by inode and type, optionally excluding a path */
static entry_t *map_lookup(hash_map_t *map, ino_t inode, kind_t type, const char *exclude_path) {
	if (!map) return NULL;

	size_t index = hash_inode(inode, type, map->size);
	hash_entry_t *hash_entry = map->buckets[index];

	while (hash_entry) {
		if (hash_entry->inode == inode && hash_entry->type == type) {
			/* Skip the excluded path (to avoid self-matching) */
			if (exclude_path && strcmp(hash_entry->entry->path, exclude_path) == 0) {
				hash_entry = hash_entry->next;
				continue;
			}
			return hash_entry->entry;
		}
		hash_entry = hash_entry->next;
	}

	return NULL;
}

/* Comparison function for sorting entries by path */
static int entry_compare(const void *a, const void *b) {
	const entry_t *entry_a = (const entry_t *) a;
	const entry_t *entry_b = (const entry_t *) b;
	return strcmp(entry_a->path, entry_b->path);
}

/* Helper function to add a path to a string array */
static bool string_add(char ***array, int *count, int *capacity, const char *path) {
	if (!array || !count || !capacity || !path) return false;

	/* Expand array if needed */
	if (*count >= *capacity) {
		int new_capacity = (*capacity == 0) ? 8 : (*capacity * 2);
		char **new_array = realloc(*array, new_capacity * sizeof(char *));
		if (!new_array) {
			log_message(ERROR, "Failed to expand string array");
			return false;
		}
		*array = new_array;
		*capacity = new_capacity;
	}

	/* Add the path */
	(*array)[*count] = strdup(path);
	if (!(*array)[*count]) {
		log_message(ERROR, "Failed to allocate memory for path: %s", path);
		return false;
	}

	(*count)++;
	return true;
}

/* Helper function to copy a string array */
static bool string_copy(char ***dest_array, int *dest_count, char **source_array, int source_count) {
	if (source_count == 0) {
		*dest_array = NULL;
		*dest_count = 0;
		return true;
	}

	*dest_array = malloc(source_count * sizeof(char *));
	if (!*dest_array) return false;

	*dest_count = source_count;
	for (int i = 0; i < source_count; i++) {
		(*dest_array)[i] = strdup(source_array[i]);
		if (!(*dest_array)[i]) {
			/* Cleanup on failure */
			for (int j = 0; j < i; j++) {
				free((*dest_array)[j]);
			}
			free(*dest_array);
			*dest_array = NULL;
			return false;
		}
	}
	return true;
}

/* Get a read-only view of a list of paths from a diff based on change type */
diff_list_t diff_list(const diff_t *diff, const char *change_type) {
	if (!diff || !change_type) {
		return (diff_list_t) {.paths = NULL, .count = 0};
	}

	if (strcmp(change_type, "created") == 0) {
		return (diff_list_t) {
			.paths = (const char *const *) diff->created,
			.count = diff->created_count
		};
	} else if (strcmp(change_type, "deleted") == 0) {
		return (diff_list_t) {
			.paths = (const char *const *) diff->deleted,
			.count = diff->deleted_count
		};
	} else if (strcmp(change_type, "renamed") == 0) {
		return (diff_list_t) {
			.paths = (const char *const *) diff->renamed,
			.count = diff->renamed_count
		};
	} else if (strcmp(change_type, "modified") == 0) {
		return (diff_list_t) {
			.paths = (const char *const *) diff->modified,
			.count = diff->modified_count
		};
	} else {
		/* "changed" is not supported as it's a compound list; consumer must handle it */
		log_message(WARNING, "Unknown or unsupported change type requested from diff_list: %s", change_type);
		return (diff_list_t) {
			.paths = NULL,
			.count = 0
		};
	}
}

/* Create a deep copy of a diff structure */
diff_t *diff_copy(const diff_t *source) {
	if (!source) return NULL;

	diff_t *copy = calloc(1, sizeof(diff_t));
	if (!copy) return NULL;

	copy->total_changes = source->total_changes;
	copy->structural_changes = source->structural_changes;

	if (!string_copy(&copy->created, &copy->created_count, source->created, source->created_count) ||
		!string_copy(&copy->deleted, &copy->deleted_count, source->deleted, source->deleted_count) ||
		!string_copy(&copy->renamed, &copy->renamed_count, source->renamed, source->renamed_count) ||
		!string_copy(&copy->modified, &copy->modified_count, source->modified, source->modified_count)) {
		diff_destroy(copy);
		return NULL;
	}

	return copy;
}

/* Destroy a diff structure and free all associated memory */
void diff_destroy(diff_t *diff) {
	if (!diff) return;

	/* Free created files array */
	if (diff->created) {
		for (int i = 0; i < diff->created_count; i++) {
			free(diff->created[i]);
		}
		free(diff->created);
	}

	/* Free deleted files array */
	if (diff->deleted) {
		for (int i = 0; i < diff->deleted_count; i++) {
			free(diff->deleted[i]);
		}
		free(diff->deleted);
	}

	/* Free renamed files array */
	if (diff->renamed) {
		for (int i = 0; i < diff->renamed_count; i++) {
			free(diff->renamed[i]);
		}
		free(diff->renamed);
	}

	/* Free modified files array */
	if (diff->modified) {
		for (int i = 0; i < diff->modified_count; i++) {
			free(diff->modified[i]);
		}
		free(diff->modified);
	}

	free(diff);
}

/* Helper function to add an entry to a snapshot */
static bool snapshot_entry(snapshot_t *snapshot, const char *relative_path, kind_t type, size_t size, time_t mtime, ino_t inode) {
	if (!snapshot || !relative_path) return false;

	/* Expand array if needed */
	if (snapshot->count >= snapshot->capacity) {
		int new_capacity = snapshot->capacity * 2;
		entry_t *new_entries = realloc(snapshot->entries, new_capacity * sizeof(entry_t));
		if (!new_entries) {
			log_message(ERROR, "Failed to expand snapshot entries array");
			return false;
		}
		snapshot->entries = new_entries;
		snapshot->capacity = new_capacity;
	}

	/* Create new entry */
	entry_t *entry = &snapshot->entries[snapshot->count];
	entry->path = strdup(relative_path);
	if (!entry->path) {
		log_message(ERROR, "Failed to allocate memory for entry path: %s", relative_path);
		return false;
	}

	entry->type = type;
	entry->size = size;
	entry->mtime = mtime;
	entry->inode = inode;

	snapshot->count++;
	return true;
}

/* Recursive directory scanning function */
static bool snapshot_scan(snapshot_t *snapshot, const char *current_path, const char *root_path, const watch_t *watch) {
	DIR *dir;
	struct dirent *dirent;
	struct stat info;
	char full_path[PATH_MAX];

	if (!snapshot || !current_path || !root_path) return false;

	/* Extract flags from watch with sensible defaults */
	bool recursive = watch ? watch->recursive : true;
	bool hidden = watch ? watch->hidden : false;

	dir = opendir(current_path);
	if (!dir) {
		log_message(WARNING, "Failed to open directory for snapshot: %s", current_path);
		return false;
	}

	while ((dirent = readdir(dir))) {
		/* Skip . and .. */
		if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0) {
			continue;
		}

		/* Build full path */
		int path_len = snprintf(full_path, sizeof(full_path), "%s/%s", current_path, dirent->d_name);
		if (path_len >= (int) sizeof(full_path)) {
			log_message(WARNING, "Path too long, skipping: %s/%s", current_path, dirent->d_name);
			continue;
		}

		/* Skip .DS_Store files created by macOS */
		if (strcmp(dirent->d_name, ".DS_Store") == 0) {
			continue;
		}

		/* Skip hidden files if not requested */
		if (!hidden && dirent->d_name[0] == '.') {
			continue;
		}

		/* Get file information */
		if (stat(full_path, &info) != 0) {
			/* Skip files that can't be stat'd but continue processing */
			continue;
		}

		/* Calculate relative path from root */
		const char *relative_path = full_path;
		if (strncmp(full_path, root_path, strlen(root_path)) == 0) {
			relative_path = full_path + strlen(root_path);
			if (*relative_path == '/') relative_path++; /* Skip leading slash */
		}

		/* Handle files */
		if (S_ISREG(info.st_mode)) {

			/* Add file entry to snapshot */
			if (!snapshot_entry(snapshot, relative_path, ENTITY_FILE,
								info.st_size, info.st_mtime, info.st_ino)) {
				closedir(dir);
				return false;
			}
		}
		/* Handle directories */
		else if (S_ISDIR(info.st_mode)) {
			/* Add directory entry to snapshot */
			if (!snapshot_entry(snapshot, relative_path, ENTITY_DIRECTORY,
								0, info.st_mtime, info.st_ino)) {
				closedir(dir);
				return false;
			}

			/* Recurse into subdirectory if recursive scanning is enabled */
			if (recursive) {
				if (!snapshot_scan(snapshot, full_path, root_path, watch)) {
					/* Continue scanning even if subdirectory fails */
					log_message(WARNING, "Failed to scan subdirectory: %s", full_path);
				}
			}
		}
	}

	closedir(dir);
	return true;
}

/* Create a snapshot of a directory tree */
snapshot_t *snapshot_create(const char *root_path, const watch_t *watch) {
	if (!root_path) {
		log_message(ERROR, "Cannot create snapshot: null root path");
		return NULL;
	}

	/* Verify root path exists and is a directory */
	struct stat root_info;
	if (stat(root_path, &root_info) != 0) {
		log_message(WARNING, "Cannot create snapshot: root path does not exist: %s", root_path);
		return NULL;
	}

	if (!S_ISDIR(root_info.st_mode)) {
		log_message(WARNING, "Cannot create snapshot: root path is not a directory: %s", root_path);
		return NULL;
	}

	/* Allocate snapshot structure */
	snapshot_t *snapshot = calloc(1, sizeof(snapshot_t));
	if (!snapshot) {
		log_message(ERROR, "Failed to allocate snapshot structure");
		return NULL;
	}

	/* Initialize snapshot */
	snapshot->root_path = strdup(root_path);
	if (!snapshot->root_path) {
		log_message(ERROR, "Failed to allocate memory for snapshot root path");
		free(snapshot);
		return NULL;
	}

	snapshot->entries = malloc(INITIAL_CAPACITY * sizeof(entry_t));
	if (!snapshot->entries) {
		log_message(ERROR, "Failed to allocate initial entries array");
		free(snapshot->root_path);
		free(snapshot);
		return NULL;
	}

	snapshot->capacity = INITIAL_CAPACITY;
	snapshot->count = 0;

	/* Scan the directory tree */
	if (!snapshot_scan(snapshot, root_path, root_path, watch)) {
		log_message(ERROR, "Failed to scan directory tree for snapshot: %s", root_path);
		snapshot_destroy(snapshot);
		return NULL;
	}

	/* Sort entries by path for efficient comparison */
	if (snapshot->count > 0) {
		qsort(snapshot->entries, snapshot->count, sizeof(entry_t), entry_compare);
	}

	return snapshot;
}

/* Destroy a snapshot and free all associated memory */
void snapshot_destroy(snapshot_t *snapshot) {
	if (!snapshot) return;

	/* Free all entry paths */
	for (int i = 0; i < snapshot->count; i++) {
		free(snapshot->entries[i].path);
	}

	/* Free arrays and structure */
	free(snapshot->entries);
	free(snapshot->root_path);
	free(snapshot);
}

/* Compare two snapshots and return the differences */
diff_t *snapshot_diff(const snapshot_t *baseline, const snapshot_t *current) {
	if (!baseline || !current) {
		log_message(ERROR, "Cannot diff snapshots: null baseline or current snapshot");
		return NULL;
	}

	/* Allocate diff structure */
	diff_t *diff = calloc(1, sizeof(diff_t));
	if (!diff) {
		log_message(ERROR, "Failed to allocate diff structure");
		return NULL;
	}

	/* Create hash maps for inode lookups */
	size_t baseline_buckets = next_prime(baseline->count + 1);
	size_t current_buckets = next_prime(current->count + 1);

	hash_map_t *baseline_map = map_create(baseline_buckets);
	hash_map_t *current_map = map_create(current_buckets);

	if (!baseline_map || !current_map) {
		log_message(ERROR, "Failed to create hash maps for snapshot diff");
		map_destroy(baseline_map);
		map_destroy(current_map);
		diff_destroy(diff);
		return NULL;
	}

	/* Populate hash maps */
	for (int i = 0; i < baseline->count; i++) {
		if (!map_insert(baseline_map, &baseline->entries[i])) {
			log_message(ERROR, "Failed to populate baseline hash map");
			map_destroy(baseline_map);
			map_destroy(current_map);
			diff_destroy(diff);
			return NULL;
		}
	}

	for (int i = 0; i < current->count; i++) {
		if (!map_insert(current_map, &current->entries[i])) {
			log_message(ERROR, "Failed to populate current hash map");
			map_destroy(baseline_map);
			map_destroy(current_map);
			diff_destroy(diff);
			return NULL;
		}
	}

	/* Initialize capacities */
	int created_capacity = 0, deleted_capacity = 0;
	int modified_capacity = 0, renamed_capacity = 0;

	/* Two-pointer comparison algorithm */
	int baseline_idx = 0, current_idx = 0;

	while (baseline_idx < baseline->count || current_idx < current->count) {
		entry_t *baseline_entry = (baseline_idx < baseline->count) ? &baseline->entries[baseline_idx] : NULL;
		entry_t *current_entry = (current_idx < current->count) ? &current->entries[current_idx] : NULL;

		int comparison;
		if (!baseline_entry) {
			comparison = 1; /* All remaining current entries are created */
		} else if (!current_entry) {
			comparison = -1; /* All remaining baseline entries are deleted */
		} else {
			comparison = strcmp(baseline_entry->path, current_entry->path);
		}

		if (comparison == 0) {
			/* Same path exists in both snapshots - check for modifications */
			if (baseline_entry->type != current_entry->type ||
				baseline_entry->size != current_entry->size ||
				baseline_entry->mtime != current_entry->mtime) {

				if (!string_add(&diff->modified, &diff->modified_count,
								&modified_capacity, current_entry->path)) {
					diff_destroy(diff);
					return NULL;
				}
			}
			baseline_idx++;
			current_idx++;

		} else if (comparison < 0) {
			/* Entry exists in baseline but not in current - it was deleted */
			/* But first check if it was renamed (moved to different path with same inode) */
			entry_t *renamed_entry = map_lookup(current_map, baseline_entry->inode,
												baseline_entry->type, baseline_entry->path);

			if (renamed_entry) {
				/* This entry was renamed/moved */
				char rename_info[PATH_MAX * 2 + 10];
				snprintf(rename_info, sizeof(rename_info), "%s -> %s",
						 baseline_entry->path, renamed_entry->path);

				if (!string_add(&diff->renamed, &diff->renamed_count,
								&renamed_capacity, rename_info)) {
					diff_destroy(diff);
					return NULL;
				}
			} else {
				/* Entry was actually deleted */
				if (!string_add(&diff->deleted, &diff->deleted_count,
								&deleted_capacity, baseline_entry->path)) {
					diff_destroy(diff);
					return NULL;
				}

				/* Track structural changes */
				if (baseline_entry->type == ENTITY_DIRECTORY) {
					diff->structural_changes = true;
				}
			}
			baseline_idx++;

		} else {
			/* Entry exists in current but not in baseline - it was created */
			/* But first check if it was renamed from a different path */
			entry_t *renamed_entry = map_lookup(baseline_map, current_entry->inode,
												current_entry->type, current_entry->path);

			if (!renamed_entry) {
				/* Entry was actually created (not renamed) */
				if (!string_add(&diff->created, &diff->created_count,
								&created_capacity, current_entry->path)) {
					diff_destroy(diff);
					return NULL;
				}

				/* Track structural changes */
				if (current_entry->type == ENTITY_DIRECTORY) {
					diff->structural_changes = true;
				}
			}
			/* If it was renamed, we already handled it in the deletion case above */
			current_idx++;
		}
	}

	/* Clean up hash maps */
	map_destroy(baseline_map);
	map_destroy(current_map);

	/* Calculate total changes */
	diff->total_changes = diff->created_count + diff->deleted_count +
						  diff->modified_count + diff->renamed_count;

	log_message(DEBUG, "Snapshot diff complete: %d created, %d deleted, %d modified, %d renamed (total: %d)",
				diff->created_count, diff->deleted_count, diff->modified_count, diff->renamed_count,
				diff->total_changes);

	return diff;
}
