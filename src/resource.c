#include "resource.h"

#include <dirent.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "events.h"
#include "logger.h"
#include "registry.h"
#include "scanner.h"
#include "snapshot.h"
#include "stability.h"

/* Free resources used by a subscription */
static void subscription_free(subscription_t *subscription) {
	if (subscription) {
		free(subscription);
	}
}

/* Check if subscription is corrupted by verifying magic number and pointer validity */
bool subscription_corrupted(const subscription_t *subscription) {
	if (!subscription) return true;

	/* Address validation - prevents crashes from invalid pointers */
	if ((uintptr_t) subscription < 0x1000 || ((uintptr_t) subscription & 0x7) != 0) {
		log_message(WARNING, "Subscription appears to be invalid pointer: %p", subscription);
		return true;
	}

	/* Magic validation with detailed logging for debugging */
	if (subscription->magic != SUBSCRIPTION_MAGIC) {
		log_message(WARNING, "Subscription corruption detected: magic=0x%x, expected=0x%x",
					subscription->magic, SUBSCRIPTION_MAGIC);
		return true;
	}
	return false;
}

/* Observer callback for watch deactivation */
static void resources_deactivation(watchref_t watchref, void *context) {
	resources_t *resources = (resources_t *) context;
	if (!resources || !resources->buckets) {
		return;
	}

	log_message(DEBUG, "Watch ID %u (gen %u) deactivated, cleaning up resources",
				watchref.watch_id, watchref.generation);

	int subscriptions_removed = 0;
	int profiles_removed = 0;
	int resources_removed = 0;

	/* Scan all buckets for subscriptions with the deactivated watch */
	for (size_t bucket = 0; bucket < resources->bucket_count; bucket++) {
		pthread_mutex_lock(&resources->bucket_mutexes[bucket]);

		resource_t **resource_ptr = &resources->buckets[bucket];
		while (*resource_ptr) {
			resource_t *resource = *resource_ptr;

			/* Lock resource for state modifications */
			pthread_mutex_lock(&resource->mutex);

			/* Remove subscriptions with deactivated watch from all profiles on this resource */
			profile_t **profile_ptr = &resource->profiles;
			while (*profile_ptr) {
				profile_t *profile = *profile_ptr;
				subscription_t **subscription_ptr = &profile->subscriptions;
				bool profile_has_subscriptions = false;

				while (*subscription_ptr) {
					subscription_t *subscription = *subscription_ptr;
					if (watchref_equal(subscription->watchref, watchref)) {
						log_message(DEBUG, "Removing deactivated subscription for path: %s",
									resource->path ? resource->path : "<null>");
						*subscription_ptr = subscription->next;
						subscription_free(subscription);
						profile->subscription_count--;
						subscriptions_removed++;
					} else {
						subscription_ptr = &subscription->next;
						profile_has_subscriptions = true;
					}
				}

				/* If profile has no subscriptions left, remove the profile */
				if (!profile_has_subscriptions) {
					log_message(DEBUG, "Removing empty scanning profile for path: %s",
								resource->path ? resource->path : "<null>");
					*profile_ptr = profile->next;
					profile_destroy(profile);
					profiles_removed++;
				} else {
					profile_ptr = &profile->next;
				}
			}

			pthread_mutex_unlock(&resource->mutex);

			/* If resource has no profiles left, remove entire resource */
			if (!resource->profiles) {
				log_message(DEBUG, "Removing empty resource after cleanup: %s",
							resource->path ? resource->path : "<null>");
				*resource_ptr = resource->next;
				pthread_mutex_destroy(&resource->mutex);
				free(resource->path);
				free(resource);
				resources_removed++;
			} else {
				resource_ptr = &resource->next;
			}
		}

		pthread_mutex_unlock(&resources->bucket_mutexes[bucket]);
	}

	if (subscriptions_removed > 0 || profiles_removed > 0 || resources_removed > 0) {
		log_message(DEBUG, "Resources cleanup: removed %d subscriptions, %d profiles, %d resources",
					subscriptions_removed, profiles_removed, resources_removed);
	}
}

/* Hash function for a path string */
unsigned int resources_hash(const char *path, size_t bucket_count) {
	unsigned int hash = 5381; /* djb2 hash initial value */
	if (!path) return 0;

	for (const char *p = path; *p; p++) {
		hash = ((hash << 5) + hash) + (unsigned char) *p;
	}

	return hash % bucket_count;
}

/* Create a new resource table */
resources_t *resources_create(size_t bucket_count, registry_t *registry) {
	resources_t *resources = calloc(1, sizeof(resources_t));
	if (!resources) {
		log_message(ERROR, "Failed to allocate memory for resource table");
		return NULL;
	}

	resources->buckets = calloc(bucket_count, sizeof(resource_t *));
	if (!resources->buckets) {
		log_message(ERROR, "Failed to allocate memory for resource table buckets");
		free(resources);
		return NULL;
	}

	resources->bucket_count = bucket_count;

	/* Allocate array of bucket mutexes */
	resources->bucket_mutexes = calloc(bucket_count, sizeof(pthread_mutex_t));
	if (!resources->bucket_mutexes) {
		log_message(ERROR, "Failed to allocate memory for bucket mutexes");
		free(resources->buckets);
		free(resources);
		return NULL;
	}

	/* Initialize all bucket mutexes (standard, non-recursive) */
	for (size_t i = 0; i < bucket_count; i++) {
		if (pthread_mutex_init(&resources->bucket_mutexes[i], NULL) != 0) {
			log_message(ERROR, "Failed to initialize bucket mutex %zu", i);
			/* Clean up previously initialized mutexes */
			for (size_t j = 0; j < i; j++) {
				pthread_mutex_destroy(&resources->bucket_mutexes[j]);
			}
			free(resources->bucket_mutexes);
			free(resources->buckets);
			free(resources);
			return NULL;
		}
	}

	/* Initialize registry integration */
	resources->registry = registry;
	resources->observer.handle_deactivation = resources_deactivation;
	resources->observer.context = resources;
	resources->observer.next = NULL;

	/* Register as observer with the registry */
	if (registry && !observer_register(registry, &resources->observer)) {
		log_message(ERROR, "Failed to register resources as observer with registry");
		resources_destroy(resources);
		return NULL;
	}

	log_message(DEBUG, "Resource table created with %zu buckets", bucket_count);
	return resources;
}

/* Free resources used by a resource and all its profiles */
static void resource_free(resource_t *resource) {
	if (resource) {
		/* Free all scanning profiles and their subscriptions */
		profile_t *profile = resource->profiles;
		while (profile) {
			profile_t *next_profile = profile->next;

			/* Free all subscriptions in this profile */
			subscription_t *subscription = profile->subscriptions;
			while (subscription) {
				subscription_t *next_subscription = subscription->next;
				subscription_free(subscription);
				subscription = next_subscription;
			}

			/* Free the profile itself */
			profile_destroy(profile);
			profile = next_profile;
		}

		/* Free any remaining deferred events */
		deferred_t *deferred = resource->deferred_head;
		while (deferred) {
			deferred_t *next_deferred = deferred->next;
			free(deferred->event.path);
			free(deferred);
			deferred = next_deferred;
		}

		pthread_mutex_destroy(&resource->mutex);
		free(resource->path);
		free(resource);
	}
}

/* Destroy a resource table */
void resources_destroy(resources_t *resources) {
	if (!resources) return;

	/* Unregister from registry observer notifications */
	if (resources->registry) {
		observer_unregister(resources->registry, &resources->observer);
	}

	/* Lock all bucket mutexes during cleanup to ensure thread safety */
	if (resources->bucket_mutexes) {
		for (size_t i = 0; i < resources->bucket_count; i++) {
			pthread_mutex_lock(&resources->bucket_mutexes[i]);
		}
	}

	if (resources->buckets) {
		/* Free all resources in all buckets */
		for (size_t bucket = 0; bucket < resources->bucket_count; bucket++) {
			resource_t *resource = resources->buckets[bucket];
			while (resource) {
				resource_t *next = resource->next;
				resource_free(resource);
				resource = next;
			}
			resources->buckets[bucket] = NULL;
		}
		free(resources->buckets);
		resources->buckets = NULL;
	}

	/* Unlock and destroy all bucket mutexes */
	if (resources->bucket_mutexes) {
		for (size_t i = 0; i < resources->bucket_count; i++) {
			pthread_mutex_unlock(&resources->bucket_mutexes[i]);
			pthread_mutex_destroy(&resources->bucket_mutexes[i]);
		}
		free(resources->bucket_mutexes);
		resources->bucket_mutexes = NULL;
	}

	free(resources);
	log_message(DEBUG, "Resource table destroyed and observer unregistered");
}

/* Get or create a resource for a given path */
resource_t *resource_get(resources_t *resources, const char *path, kind_t kind) {
	if (!resources || !path || !resources->buckets) {
		log_message(ERROR, "Invalid arguments to resource_get");
		return NULL;
	}

	unsigned int hash = resources_hash(path, resources->bucket_count);

	/* Lock only the specific bucket mutex for this path */
	pthread_mutex_lock(&resources->bucket_mutexes[hash]);

	resource_t *resource = resources->buckets[hash];

	/* Find existing resource */
	while (resource) {
		if (strcmp(resource->path, path) == 0) {
			break;
		}
		resource = resource->next;
	}

	/* If resource not found, create it */
	if (!resource) {
		resource = calloc(1, sizeof(resource_t));
		if (!resource) {
			log_message(ERROR, "Failed to allocate memory for resource: %s", path);
			pthread_mutex_unlock(&resources->bucket_mutexes[hash]);
			return NULL;
		}
		resource->path = strdup(path);
		if (!resource->path) {
			log_message(ERROR, "Failed to duplicate path for resource: %s", path);
			free(resource);
			pthread_mutex_unlock(&resources->bucket_mutexes[hash]);
			return NULL;
		}

		/* Initialize resource mutex */
		if (pthread_mutex_init(&resource->mutex, NULL) != 0) {
			log_message(ERROR, "Failed to initialize resource mutex for: %s", path);
			free(resource->path);
			free(resource);
			pthread_mutex_unlock(&resources->bucket_mutexes[hash]);
			return NULL;
		}

		/* Initialize resource state */
		resource->executing = false;
		resource->kind = kind;
		resource->profiles = NULL;

		/* Initialize deferred event queue */
		resource->deferred_head = NULL;
		resource->deferred_tail = NULL;
		resource->deferred_count = 0;

		/* Determine resource type and existence from filesystem */
		struct stat info;
		resource->exists = (stat(path, &info) == 0);

		if (kind == ENTITY_UNKNOWN && resource->exists) {
			if (S_ISDIR(info.st_mode)) resource->kind = ENTITY_DIRECTORY;
			else if (S_ISREG(info.st_mode)) resource->kind = ENTITY_FILE;
		} else if (kind != ENTITY_UNKNOWN) resource->kind = kind;

		/* Initialize timestamps on the resource */
		clock_gettime(CLOCK_MONOTONIC, &resource->last_time);
		clock_gettime(CLOCK_REALTIME, &resource->wall_time);
		resource->op_time.tv_sec = 0;
		resource->op_time.tv_nsec = 0;
		resource->content_changed = false;
		resource->metadata_changed = false;
		resource->structure_changed = false;

		/* Add to hash bucket */
		resource->next = resources->buckets[hash];
		resources->buckets[hash] = resource;
	}

	pthread_mutex_unlock(&resources->bucket_mutexes[hash]);
	return resource;
}

/* Resource locking functions */
void resource_lock(resource_t *resource) {
	if (resource) {
		pthread_mutex_lock(&resource->mutex);
	}
}

void resource_unlock(resource_t *resource) {
	if (resource) {
		pthread_mutex_unlock(&resource->mutex);
	}
}

/* Hash watch configuration using FNV-1a algorithm */
uint64_t configuration_hash(const watch_t *watch) {
	if (!watch) return 0;

	/* Use FNV-1a hash algorithm */
	uint64_t hash = 14695981039346656037ULL; /* FNV offset basis */
	const uint64_t prime = 1099511628211ULL; /* FNV prime */

	/* Hash boolean flags */
	hash ^= (uint64_t) (watch->recursive ? 1 : 0);
	hash *= prime;
	hash ^= (uint64_t) (watch->hidden ? 1 : 0);
	hash *= prime;

	/* Hash exclude patterns */
	if (watch->exclude && watch->num_exclude > 0) {
		for (int i = 0; i < watch->num_exclude; i++) {
			if (watch->exclude[i]) {
				const char *pattern = watch->exclude[i];
				while (*pattern) {
					hash ^= (uint64_t) (*pattern);
					hash *= prime;
					pattern++;
				}
			}
		}
	}

	return hash;
}

/* Find existing scanning profile with matching configuration hash */
profile_t *profile_get(resource_t *resource, uint64_t configuration_hash) {
	if (!resource) return NULL;

	profile_t *profile = resource->profiles;
	while (profile) {
		if (profile->configuration_hash == configuration_hash) {
			return profile;
		}
		profile = profile->next;
	}
	return NULL;
}

/* Create a new scanning profile */
profile_t *profile_create(resource_t *resource, uint64_t configuration_hash) {
	if (!resource) return NULL;

	profile_t *profile = calloc(1, sizeof(profile_t));
	if (!profile) {
		log_message(ERROR, "Failed to allocate memory for scanning profile");
		return NULL;
	}

	profile->configuration_hash = configuration_hash;
	profile->stability = NULL;
	profile->scanner = NULL;
	profile->baseline_snapshot = NULL;
	profile->subscriptions = NULL;
	profile->subscription_count = 0;
	profile->next = NULL;

	/* Add the new profile to the resource */
	profile->next = resource->profiles;
	resource->profiles = profile;

	return profile;
}

/* Destroy a scanning profile and all its resources */
void profile_destroy(profile_t *profile) {
	if (profile) {
		stability_destroy(profile->stability);
		scanner_destroy(profile->scanner);
		snapshot_destroy(profile->baseline_snapshot);
		free(profile);
	}
}

/* Create a subscription within a profile */
subscription_t *profile_subscribe(profile_t *profile, resource_t *resource, watchref_t watchref) {
	if (!profile || !resource || !watchref_valid(watchref)) {
		return NULL;
	}

	/* Check if subscription already exists */
	subscription_t *existing = profile_subscription(profile, watchref);
	if (existing) {
		return existing;
	}

	/* Create new subscription */
	subscription_t *subscription = calloc(1, sizeof(subscription_t));
	if (!subscription) {
		log_message(ERROR, "Failed to allocate memory for subscription");
		return NULL;
	}

	/* Initialize subscription as lightweight link */
	subscription->magic = SUBSCRIPTION_MAGIC;
	subscription->resource = resource;
	subscription->watchref = watchref;
	subscription->profile = profile;
	subscription->command_time = 0;

	/* Add to the profile's subscription list */
	subscription->next = profile->subscriptions;
	profile->subscriptions = subscription;
	profile->subscription_count++;

	log_message(DEBUG, "Subscription created for resource: %s (watch_id=%u, gen=%u, total_subscriptions=%d)",
				resource->path ? resource->path : "<unknown>", watchref.watch_id,
				watchref.generation, profile->subscription_count);

	return subscription;
}

/* Remove a subscription from a profile */
bool profile_unsubscribe(profile_t *profile, watchref_t watchref) {
	if (!profile || !watchref_valid(watchref)) {
		return false;
	}

	subscription_t **subscription_ptr = &profile->subscriptions;
	while (*subscription_ptr) {
		subscription_t *subscription = *subscription_ptr;
		if (watchref_equal(subscription->watchref, watchref)) {
			*subscription_ptr = subscription->next;
			subscription_free(subscription);
			profile->subscription_count--;
			return true;
		}
		subscription_ptr = &subscription->next;
	}
	return false;
}

/* Find a subscription within a profile */
subscription_t *profile_subscription(profile_t *profile, watchref_t watchref) {
	if (!profile || !watchref_valid(watchref)) return NULL;

	subscription_t *subscription = profile->subscriptions;
	while (subscription) {
		if (watchref_equal(subscription->watchref, watchref)) {
			return subscription;
		}
		subscription = subscription->next;
	}
	return NULL;
}

/* Finds or creates a complete subscription chain for a given path and watch */
subscription_t *resources_subscription(resources_t *resources, registry_t *registry, const char *path, watchref_t watchref, kind_t kind) {
	if (!resources || !path || !watchref_valid(watchref) || !registry) return NULL;

	/* Validate watch reference against registry */
	if (!registry_valid(registry, watchref)) {
		log_message(WARNING, "Watch reference is invalid or deactivated");
		return NULL;
	}

	/* Get watch for configuration and logging purposes */
	watch_t *watch = registry_get(registry, watchref);
	if (!watch || !watch->name) {
		log_message(ERROR, "Could not resolve watch from registry for path %s", path);
		return NULL;
	}

	/* Get or create resource (with bucket-level locking) */
	resource_t *resource = resource_get(resources, path, kind);
	if (!resource) return NULL;

	/* Lock resource for profile/subscription operations */
	resource_lock(resource);

	/* Calculate configuration hash for this watch */
	uint64_t watch_hash = configuration_hash(watch);

	/* Find existing scanning profile with matching configuration */
	profile_t *profile = profile_get(resource, watch_hash);

	/* If no matching profile found, create a new one */
	if (profile) goto create_subscription;

	/* For directories, pre-scan before creating profile to avoid holding lock during I/O */
	stats_t initial_stats;
	bool scan_success = false;
	bool is_directory = (resource->kind == ENTITY_DIRECTORY && resource->exists);

	if (is_directory) {
		/* Release resource lock before scanning to prevent blocking other threads */
		resource_unlock(resource);

		/* Perform initial scan without holding the lock */
		scan_success = scanner_scan(path, watch, &initial_stats);

		/* Re-acquire lock and check if another thread created the profile */
		resource_lock(resource);

		/* Check again if profile was created while we were scanning */
		profile = profile_get(resource, watch_hash);
		if (profile) {
			/* Another thread created the profile - use the existing one and discard our scan */
			log_message(DEBUG, "Profile created by another thread during scan for %s", path);
			goto create_subscription;
		}
	}

	/* Create the profile now */
	profile = profile_create(resource, watch_hash);
	if (!profile) {
		log_message(ERROR, "Failed to create scanning profile for %s", path);
		resource_unlock(resource);
		return NULL;
	}

	/* Initialize the profile for directories with pre-scanned data */
	if (!is_directory) goto create_subscription;

	/* Create stability state for this configuration */
	profile->stability = stability_create();
	if (!profile->stability) {
		log_message(ERROR, "Failed to create stability state for directory: %s", path);
		resource_unlock(resource);
		return NULL;
	}

	/* Use pre-scanned data if scan was successful */
	if (!scan_success) {
		log_message(WARNING, "Failed to gather initial stats for directory: %s", path);
		goto create_subscription;
	}

	profile->stability->stats = initial_stats;
	profile->stability->prev_stats = initial_stats;
	profile->stability->ref_stats = initial_stats;
	profile->stability->reference_init = true;

	/* Create initial baseline snapshot for accurate change detection */
	profile->baseline_snapshot = snapshot_create(path, watch);
	if (!profile->baseline_snapshot) {
		log_message(WARNING, "Failed to create initial baseline snapshot for directory: %s", path);
		/* Continue without snapshot - system will fall back to time-based detection */
	} else {
		log_message(DEBUG, "Created initial baseline snapshot for %s with %d entries",
					path, profile->baseline_snapshot->count);
	}

	log_message(DEBUG, "Initial baseline established for %s: files=%d, dirs=%d, depth=%d, size=%s",
				path, profile->stability->stats.tree_files, profile->stability->stats.tree_dirs,
				profile->stability->stats.max_depth,
				format_size((ssize_t) profile->stability->stats.tree_size, false));

create_subscription:
	/* Create subscription linking this watch to the profile */
	{
		subscription_t *subscription = profile_subscribe(profile, resource, watchref);
		if (!subscription) {
			log_message(ERROR, "Failed to create subscription for %s", path);
		}

		resource_unlock(resource);
		return subscription;
	}
}
