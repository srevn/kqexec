#ifndef UTILITIES_H
#define UTILITIES_H

#include <time.h>
#include <stdbool.h>

/* Timespec utilities functions */
void timespec_add(struct timespec *ts, int milliseconds);
bool timespec_after(const struct timespec *a, const struct timespec *b);
bool timespec_before(const struct timespec *a, const struct timespec *b);
long timespec_diff(const struct timespec *a, const struct timespec *b);

#endif /* UTILITIES_H */
