#define _GNU_SOURCE

#include "src/core/shadow/probes/fork.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int fork_write_value(int descriptor, uint64_t value) {
	const unsigned char *bytes = (const unsigned char *)&value;
	size_t written = 0;

	while (written < sizeof(value)) {
		ssize_t count = write(descriptor, bytes + written,
				      sizeof(value) - written);

		if (count > 0) {
			written += (size_t)count;
			continue;
		}
		if (count < 0 && errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

static int fork_read_value(int descriptor, uint64_t *value) {
	unsigned char *bytes = (unsigned char *)value;
	size_t read_size = 0;

	while (read_size < sizeof(*value)) {
		ssize_t count = read(descriptor, bytes + read_size,
				     sizeof(*value) - read_size);

		if (count > 0) {
			read_size += (size_t)count;
			continue;
		}
		if (count < 0 && errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

int fork_probe(const struct poirot_target *target,
	       const struct poirot_options *options,
	       struct poirot_fork_result *result) {
	const uint64_t input = UINT64_C(0x504f4952);
	struct pollfd descriptor;
	int pipe_fds[2];
	pid_t child;
	int poll_result;
	int status = 0;
	pid_t waited;

	if (!target || !target->target || !target->expected || !options ||
	    !result || !options->fork_timeout_ms)
		return -EINVAL;
	if (pipe2(pipe_fds, O_CLOEXEC) != 0)
		return -errno;

	result->expected = target->expected(input, target->expected_context);
	(void)target->target(input);
	child = fork();
	if (child < 0) {
		int error = -errno;

		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return error;
	}
	if (!child) {
		uint64_t value;

		close(pipe_fds[0]);
		value = target->target(input);
		_exit(fork_write_value(pipe_fds[1], value) == 0 ? 0 : 127);
	}

	close(pipe_fds[1]);
	result->parent_value = target->target(input);
	descriptor.fd = pipe_fds[0];
	descriptor.events = POLLIN;
	descriptor.revents = 0;
	do {
		poll_result =
			poll(&descriptor, 1, (int)options->fork_timeout_ms);
	} while (poll_result < 0 && errno == EINTR);

	if (!poll_result) {
		result->timed_out = 1;
		(void)kill(child, SIGKILL);
	} else if (poll_result < 0 ||
		   !(descriptor.revents & (POLLIN | POLLHUP)) ||
		   fork_read_value(pipe_fds[0], &result->child_value) != 0) {
		result->error = poll_result < 0 ? errno : EIO;
	}
	close(pipe_fds[0]);

	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited < 0 && !result->error)
		result->error = errno;
	result->child_status = status;
	if (result->timed_out)
		result->status = POIROT_PROBE_SUSPICIOUS;
	else if (result->error || !WIFEXITED(status) || WEXITSTATUS(status))
		result->status = POIROT_PROBE_ERROR;
	else if (result->parent_value != result->child_value ||
		 result->parent_value != result->expected ||
		 result->child_value != result->expected)
		result->status = POIROT_PROBE_SUSPICIOUS;
	else
		result->status = POIROT_PROBE_CLEAN;
	return 0;
}
