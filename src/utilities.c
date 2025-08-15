#include "utilities.h"

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
