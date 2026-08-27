#ifndef POIROT_UTILS_SIGNAL_H
#define POIROT_UTILS_SIGNAL_H

#include <signal.h>
#include <stdint.h>

uintptr_t signal_pc(void *raw_context);
uintptr_t signal_lr(void *raw_context);
void signal_forward(const struct sigaction *action, int signal_number,
		    siginfo_t *info, void *raw_context);

#endif
