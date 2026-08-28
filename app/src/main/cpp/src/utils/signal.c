#define _GNU_SOURCE

#include "signal.h"

#include <errno.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

uintptr_t signal_pc(void *raw_context) {
#if defined(__aarch64__)
	ucontext_t *context = raw_context;

	return (uintptr_t)context->uc_mcontext.pc;
#else
	(void)raw_context;
	return 0;
#endif
}

uintptr_t signal_lr(void *raw_context) {
#if defined(__aarch64__)
	ucontext_t *context = raw_context;

	return (uintptr_t)context->uc_mcontext.regs[30];
#else
	(void)raw_context;
	return 0;
#endif
}

int signal_set_pc(void *raw_context, uintptr_t pc) {
#if defined(__aarch64__)
	ucontext_t *context = raw_context;

	if (!context)
		return -EINVAL;
	context->uc_mcontext.pc = (unsigned long)pc;
	return 0;
#else
	(void)raw_context;
	(void)pc;
	return -ENOTSUP;
#endif
}

int signal_set_register(void *raw_context, unsigned int index,
			uintptr_t value) {
#if defined(__aarch64__)
	ucontext_t *context = raw_context;

	if (!context || index >= 31)
		return -EINVAL;
	context->uc_mcontext.regs[index] = (unsigned long)value;
	return 0;
#else
	(void)raw_context;
	(void)index;
	(void)value;
	return -ENOTSUP;
#endif
}

void signal_forward(const struct sigaction *action, int signal_number,
		    siginfo_t *info, void *raw_context) {
	if (action->sa_handler == SIG_IGN)
		return;
	if (action->sa_handler == SIG_DFL) {
		pid_t tid = (pid_t)syscall(SYS_gettid);

		(void)sigaction(signal_number, action, NULL);
		(void)syscall(SYS_tgkill, getpid(), tid, signal_number);
		return;
	}
	if (action->sa_flags & SA_SIGINFO)
		action->sa_sigaction(signal_number, info, raw_context);
	else
		action->sa_handler(signal_number);
}
