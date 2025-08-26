#ifndef UTILITIES_H
#define UTILITIES_H

#include <stdbool.h>
#include <time.h>

/* Timespec utilities functions */
void timespec_add(struct timespec *ts, int milliseconds);
bool timespec_after(const struct timespec *a, const struct timespec *b);
bool timespec_before(const struct timespec *a, const struct timespec *b);
long timespec_diff(const struct timespec *a, const struct timespec *b);

/* Complexity-based scaling functions */
double complexity_batch(double complexity);
double complexity_responsiveness(double complexity);
double complexity_backoff(double complexity);
double complexity_stability(double complexity);
double complexity_sensitivity(double complexity, int change_level);
double complexity_temporary(double complexity);

#endif /* UTILITIES_H */
