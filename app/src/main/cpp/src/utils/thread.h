#ifndef POIROT_UTILS_THREAD_H
#define POIROT_UTILS_THREAD_H

int thread_choose_cpus(int *first, int *second);
int thread_pin(int cpu);

#endif
