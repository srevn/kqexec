#ifndef RESOURCE_H
#define RESOURCE_H

#include <pthread.h>
#include <stdint.h>
#include <time.h>

#include "config.h"
#include "registry.h"
#include "scanner.h"

/* Forward declarations */
typedef struct stability stability_t;

/* Resource table configuration */
#define PATH_HASH_SIZE 1024
#define SUBSCRIPTION_MAGIC 0x4B514558      /* "KQEX" */

/* Scanning profile for watches with compatible scan configurations */
typedef struct profile {
	uint64_t configuration_hash;           /* Hash of the scan configuration (recursive, hidden, excludes) */
	
	/* Configuration-specific state */
	stability_t *stability;                /* Shared stability state for this profile */
	scanner_t *scanner;                    /* Shared scanner state for this profile */
	
	/* Subscriptions using this configuration */
	subscription_t *subscriptions;         /* Head of list of subscriptions with this profile */
	int subscription_count;                /* Reference counter for cleanup */
	
	struct profile *next;                  /* Next profile for the same resource */
} profile_t;

/* Resource for a given path, holding all scanning profiles for that path */
typedef struct resource {
	char *path;                            /* The filesystem path */
	kind_t kind;                           /* File or directory */
	
	/* Basic filesystem state */
	bool exists;                           /* Resource currently exists */
	bool content_changed;                  /* Content has changed */
	bool metadata_changed;                 /* Metadata has changed */
	bool structure_changed;                /* Structural change occurred */
	
	/* Timestamps */
	struct timespec last_time;             /* When state was last updated (MONOTONIC) */
	struct timespec wall_time;             /* Wall clock time (REALTIME) */
	struct timespec op_time;               /* Timestamp of the last operation to prevent duplicates */
	
	/* Scanning profiles */
	profile_t *profiles;                   /* Head of list of scanning profiles */
	
	/* Execution state */
	bool executing;                        /* Flag indicating command is currently executing on this path */
	pthread_mutex_t mutex;                 /* Resource-level mutex */

	/* Deferred events queue */
	struct deferred *deferred_head;        /* Head of the deferred event queue */
	struct deferred *deferred_tail;        /* Tail of the deferred event queue */
	int deferred_count;                    /* Number of events in the queue */
	
	struct resource *next;                 /* Next resource in the hash bucket */
} resource_t;

/* Resource table structure */
typedef struct resources {
	resource_t **buckets;                  /* Hash table buckets for path resources */
	size_t bucket_count;                   /* Number of buckets in the hash table */
	pthread_mutex_t *bucket_mutexes;       /* Array of mutexes, one per bucket */
	registry_t *registry;                  /* Registry reference for lookups */
	observer_t observer;                   /* Observer registration for cleanup */
} resources_t;

/* Subscription tracking structure */
typedef struct subscription {
	/* Core identity */
	uint32_t magic;                        /* Magic number for corruption detection */
	resource_t *resource;                  /* Back-pointer to the parent resource */
	watchref_t watchref;                   /* Watch reference for this subscription */

	/* Command & Trigger tracking */
	time_t command_time;                   /* When a command was last triggered */
	char *trigger;                         /* Path of the specific file that triggered a directory event */
	
	/* Profile association */
	profile_t *profile;                    /* The scanning profile this subscription belongs to */

	/* Linkage for all subscriptions under the same profile */
	struct subscription *next;             /* Next subscription for the same profile */
} subscription_t;

/* Resource table management */
resources_t *resources_create(size_t bucket_count, registry_t *registry);
void resources_destroy(resources_t *resources);
unsigned int resources_hash(const char *path, size_t bucket_count);

/* Resource management */
resource_t *resource_get(resources_t *resources, const char *path, kind_t kind);
void resource_lock(resource_t *resource);
void resource_unlock(resource_t *resource);

/* Configuration utilities */
uint64_t configuration_hash(const watch_t *watch);

/* Profile management */
profile_t *profile_get(resource_t *resource, uint64_t configuration_hash);
profile_t *profile_create(resource_t *resource, uint64_t configuration_hash);
void profile_destroy(profile_t *profile);

/* Subscription management */
subscription_t *profile_subscribe(profile_t *profile, resource_t *resource, watchref_t watchref);
bool profile_unsubscribe(profile_t *profile, watchref_t watchref);
subscription_t *profile_subscription(profile_t *profile, watchref_t watchref);
bool subscription_corrupted(const subscription_t *subscription);

/* Main entry point */
subscription_t *resources_subscription(resources_t *resources, registry_t *registry, const char *path, watchref_t watchref, kind_t kind);

#endif /* RESOURCE_H */
