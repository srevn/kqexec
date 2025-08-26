#include "utilities.h"

#include <math.h>
#include <string.h>

/* Add milliseconds to a timespec */
void timespec_add(struct timespec *ts, int milliseconds) {
	ts->tv_sec += milliseconds / 1000;
	ts->tv_nsec += (milliseconds % 1000) * 1000000;

	/* Normalize nsec */
	if (ts->tv_nsec >= 1000000000) {
		ts->tv_sec++;
		ts->tv_nsec -= 1000000000;
	}
}

/* Check if timespec a is after timespec b */
bool timespec_after(const struct timespec *a, const struct timespec *b) {
	if (a->tv_sec > b->tv_sec) return true;
	if (a->tv_sec == b->tv_sec && a->tv_nsec > b->tv_nsec) return true;
	return false;
}

/* Check if timespec a is before timespec b */
bool timespec_before(const struct timespec *a, const struct timespec *b) {
	if (a->tv_sec < b->tv_sec) return true;
	if (a->tv_sec == b->tv_sec && a->tv_nsec < b->tv_nsec) return true;
	return false;
}

/* Calculate difference between two timespecs in milliseconds (a - b) */
long timespec_diff(const struct timespec *a, const struct timespec *b) {
	long sec_diff = a->tv_sec - b->tv_sec;
	long nsec_diff = a->tv_nsec - b->tv_nsec;
	return sec_diff * 1000 + nsec_diff / 1000000;
}

/* Calculate batch timeout threshold factor based on complexity (0.1-1.0 range)
 * Higher complexity = higher threshold (more patient with ongoing activity)
 * Baseline: complexity 1.0 = factor 0.5 */
double complexity_batch(double complexity) {
	if (complexity <= 0.0) complexity = 1.0;

	double factor;
	if (complexity <= 1.0) {
		/* For complexity <= 1.0, scale linearly from 0.1 to 0.5 (baseline) */
		factor = 0.1 + 0.4 * complexity;
	} else {
		/* For complexity > 1.0, use logarithmic scaling from 0.5 to 1.0 (max at 5.0) */
		factor = 0.5 + 0.5 * (log(complexity) / log(5.0));
	}

	/* Clamp to valid range */
	if (factor < 0.1) factor = 0.1;
	if (factor > 1.0) factor = 1.0;

	return factor;
}

/* Calculate responsiveness factor for complexity drops (0.1-1.0 range)
 * Higher complexity = higher factor = higher threshold = less willing to drop quiet periods
 * Baseline: complexity 1.0 = factor 0.75 */
double complexity_responsiveness(double complexity) {
	if (complexity <= 0.0) complexity = 1.0;

	double factor;
	if (complexity <= 1.0) {
		/* For complexity <= 1.0, scale linearly from 0.25 to 0.75 (baseline) */
		factor = 0.25 + 0.5 * complexity;
	} else {
		/* For complexity > 1.0, use logarithmic growth from 0.75 to 1.0 (max at 5.0) */
		factor = 0.75 + 0.25 * (log(complexity) / log(5.0));
	}

	/* Clamp to valid range */
	if (factor < 0.25) factor = 0.25;
	if (factor > 1.0) factor = 1.0;

	return factor;
}

/* Calculate backoff intensity multiplier based on complexity (1.0-2.5 range)
 * Higher complexity = more aggressive backoff
 * Baseline: complexity 1.0 = factor 1.5 */
double complexity_backoff(double complexity) {
	if (complexity <= 0.0) complexity = 1.0;

	double factor;
	if (complexity <= 1.0) {
		/* For complexity <= 1.0, scale linearly from 1.0 to 1.5 (baseline) */
		factor = 1.0 + 0.5 * complexity;
	} else {
		/* For complexity > 1.0, use logarithmic growth from 1.5 to 2.5 (max at 5.0) */
		factor = 1.5 + 1.0 * (log(complexity) / log(5.0));
	}

	/* Clamp to valid range */
	if (factor < 1.0) factor = 1.0;
	if (factor > 2.5) factor = 2.5;

	return factor;
}

/* Calculate stability factor for quiet period scaling (1.0-3.0 range)
 * Higher complexity = longer quiet periods */
double complexity_stability(double complexity) {
	if (complexity <= 0.0) complexity = 1.0;

	/* Use logarithmic growth for smooth scaling */
	double factor;
	if (complexity <= 1.0) {
		/* For complexity < 1.0, scale down from 1.0 */
		factor = complexity;
	} else {
		/* For complexity > 1.0, use logarithmic growth */
		factor = 1.0 + 1.4 * log(complexity);
	}

	/* Clamp to valid range */
	if (factor < 0.1) factor = 0.1; /* Allow very low complexity to go below 1.0 */
	if (factor > 3.0) factor = 3.0;

	return factor;
}

/* Calculate sensitivity factor based on complexity and change level
 * Higher complexity = higher factor = longer delays = less responsive
 * Baseline: complexity 1.0 = factor 1.0 (no change) */
double complexity_sensitivity(double complexity, int change_level) {
	if (complexity <= 0.0) complexity = 1.0;

	/* Base factor increases with complexity (higher complexity = less responsive) */
	double base_factor;
	if (complexity <= 1.0) {
		/* For complexity <= 1.0, scale linearly from 0.5 to 1.0 (baseline) */
		base_factor = 0.5 + 0.5 * complexity;
	} else {
		/* For complexity > 1.0, use logarithmic growth from 1.0 to 2.5 (max at 5.0) */
		base_factor = 1.0 + 1.5 * (log(complexity) / log(5.0));
	}

	/* Adjust based on change level:
	 * change_level 0: small changes - apply full complexity scaling
	 * change_level 1: medium changes - apply moderate complexity scaling
	 * change_level 2+: large changes - apply minimal complexity scaling */
	double factor;
	switch (change_level) {
		case 0: /* Small changes - full complexity effect */
			factor = base_factor;
			break;
		case 1: /* Medium changes - moderate complexity effect */
			factor = 0.7 + 0.3 * base_factor;
			break;
		default: /* Large changes - minimal complexity effect */
			factor = 0.8 + 0.2 * base_factor;
			break;
	}

	/* Clamp to reasonable range */
	if (factor < 0.5) factor = 0.5;
	if (factor > 2.5) factor = 2.5;

	return factor;
}

/* Calculate temporary file threshold based on complexity (0.2s-5.0s range)
 * Higher complexity = higher threshold = more patient with recent file changes
 * Baseline: complexity 1.0 = threshold 1.0s (current default) */
double complexity_temporary(double complexity) {
	if (complexity <= 0.0) complexity = 1.0;

	double threshold;
	if (complexity <= 1.0) {
		/* For complexity <= 1.0, scale linearly from 0.25s to 1.0s (baseline) */
		threshold = 0.2 + 0.75 * complexity;
	} else {
		/* For complexity > 1.0, use logarithmic growth from 1.0s to 5.0s */
		threshold = 1.0 + 4.0 * (log(complexity) / log(5.0));
	}

	/* Clamp to valid range */
	if (threshold < 0.2) threshold = 0.2;
	if (threshold > 5.0) threshold = 5.0;

	return threshold;
}
