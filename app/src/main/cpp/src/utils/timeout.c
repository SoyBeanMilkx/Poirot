#define _GNU_SOURCE

#include "timeout.h"

#include "time.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

struct poirot_watchdog {
	pthread_t caller;
	int cancel_fd;
	int signal_number;
	uint32_t timeout_ms;
};

static pthread_mutex_t timeout_lock = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local sigjmp_buf timeout_environment;
static _Thread_local volatile sig_atomic_t timeout_armed;

static void timeout_signal_handler(int signal_number) {
	(void)signal_number;
	if (!timeout_armed)
		return;
	timeout_armed = 0;
	siglongjmp(timeout_environment, 1);
}

static void *timeout_watchdog(void *argument) {
	struct poirot_watchdog *watchdog = argument;
	struct pollfd descriptor = {
		.fd = watchdog->cancel_fd,
		.events = POLLIN,
	};
	int result;

	do {
		result = poll(&descriptor, 1, (int)watchdog->timeout_ms);
	} while (result < 0 && errno == EINTR);

	if (!result)
		(void)pthread_kill(watchdog->caller, watchdog->signal_number);
	return NULL;
}

static void timeout_consume_pending(int signal_number) {
	sigset_t pending;
	struct timespec zero = {0, 0};

	if (sigpending(&pending) == 0 &&
	    sigismember(&pending, signal_number) == 1) {
		sigset_t one;

		sigemptyset(&one);
		sigaddset(&one, signal_number);
		(void)sigtimedwait(&one, NULL, &zero);
	}
}

int poirot_timeout_call(poirot_timeout_fn function, uint32_t timeout_ms,
			struct poirot_timeout_result *result) {
	const int signal_number = SIGRTMIN + 6;
	struct poirot_watchdog watchdog;
	struct sigaction action;
	struct sigaction old_action;
	sigset_t old_mask;
	sigset_t run_mask;
	sigset_t blocked_mask;
	pthread_t thread;
	uint64_t started;
	int pipe_fds[2] = {-1, -1};
	int error;
	int thread_started = 0;
	char cancel = 1;

	if (!function || !result || !timeout_ms || signal_number > SIGRTMAX)
		return -EINVAL;
	memset(result, 0, sizeof(*result));

	error = pthread_mutex_lock(&timeout_lock);
	if (error)
		return -error;

	if (pipe2(pipe_fds, O_CLOEXEC | O_NONBLOCK) != 0) {
		error = -errno;
		goto unlock;
	}

	memset(&action, 0, sizeof(action));
	action.sa_handler = timeout_signal_handler;
	sigemptyset(&action.sa_mask);
	if (sigaction(signal_number, &action, &old_action) != 0) {
		error = -errno;
		goto close_pipe;
	}

	error = pthread_sigmask(SIG_SETMASK, NULL, &old_mask);
	if (error) {
		error = -error;
		goto restore_action;
	}
	run_mask = old_mask;
	sigdelset(&run_mask, signal_number);
	error = pthread_sigmask(SIG_SETMASK, &run_mask, NULL);
	if (error) {
		error = -error;
		goto restore_action;
	}

	watchdog.caller = pthread_self();
	watchdog.cancel_fd = pipe_fds[0];
	watchdog.signal_number = signal_number;
	watchdog.timeout_ms = timeout_ms;
	error = pthread_create(&thread, NULL, timeout_watchdog, &watchdog);
	if (error) {
		error = -error;
		goto restore_mask;
	}
	thread_started = 1;

	started = poirot_time_now_ns();
	timeout_armed = 1;
	if (sigsetjmp(timeout_environment, 1) == 0)
		result->value = function();
	else
		result->timed_out = 1;
	timeout_armed = 0;
	result->elapsed_ns = poirot_time_now_ns() - started;

	(void)write(pipe_fds[1], &cancel, sizeof(cancel));
	if (thread_started)
		(void)pthread_join(thread, NULL);

	blocked_mask = run_mask;
	sigaddset(&blocked_mask, signal_number);
	(void)pthread_sigmask(SIG_SETMASK, &blocked_mask, NULL);
	timeout_consume_pending(signal_number);
	error = 0;

restore_mask:
	(void)pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
restore_action:
	(void)sigaction(signal_number, &old_action, NULL);
close_pipe:
	close(pipe_fds[0]);
	close(pipe_fds[1]);
unlock:
	(void)pthread_mutex_unlock(&timeout_lock);
	return error;
}
