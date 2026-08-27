#ifndef POIROT_UTILS_THREAD_H
#define POIROT_UTILS_THREAD_H

int poirot_thread_choose_cpus(int *first, int *second);
int poirot_thread_pin(int cpu);

#endif
