#define _GNU_SOURCE

#include "ghost.h"

#include "src/utils/memory.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

struct ghost_observation {
	int readable;
	int noreplace_errno;
	unsigned char value;
};

static int ghost_write(int descriptor,
		       const struct ghost_observation *observation) {
	const unsigned char *bytes = (const unsigned char *)observation;
	size_t offset = 0;

	while (offset < sizeof(*observation)) {
		ssize_t count = write(descriptor, bytes + offset,
				      sizeof(*observation) - offset);

		if (count > 0) {
			offset += (size_t)count;
			continue;
		}
		if (count < 0 && errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

static int ghost_read(int descriptor, struct ghost_observation *observation) {
	unsigned char *bytes = (unsigned char *)observation;
	size_t offset = 0;

	while (offset < sizeof(*observation)) {
		ssize_t count = read(descriptor, bytes + offset,
				     sizeof(*observation) - offset);

		if (count > 0) {
			offset += (size_t)count;
			continue;
		}
		if (count < 0 && errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

int redirect_ghost_probe(uintptr_t address, size_t page_size,
			 const struct poirot_options *options,
			 struct poirot_redirect_ghost_result *result) {
	struct ghost_observation observation = {0};
	struct poirot_memory_region region;
	struct pollfd descriptor;
	uintptr_t page;
	int pipe_fds[2];
	pid_t child;
	pid_t waited;
	int poll_result;
	int status = 0;
	int error;

	if (!memory_user_address(address) || !page_size || !options ||
	    !result ||
	    !options->redirect_timeout_ms)
		return -EINVAL;
	error = memory_query(address, &region);
	if (!error)
		return -EEXIST;
	if (error != -ENOENT)
		return error;

	page = memory_page_start(address, page_size);
	result->address = page;
	if (pipe2(pipe_fds, O_CLOEXEC) != 0)
		return -errno;

	child = fork();
	if (child < 0) {
		error = -errno;
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return error;
	}
	if (!child) {
		void *mapped;

		close(pipe_fds[0]);
		observation.value =
			*(volatile const unsigned char *)(uintptr_t)address;
		observation.readable = 1;
		errno = 0;
		mapped = mmap((void *)page, page_size, PROT_NONE,
			      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
			      -1, 0);
		if (mapped == MAP_FAILED)
			observation.noreplace_errno = errno;
		else
			(void)munmap(mapped, page_size);
		_exit(ghost_write(pipe_fds[1], &observation) == 0 ? 0 : 127);
	}

	close(pipe_fds[1]);
	descriptor = (struct pollfd){
		.fd = pipe_fds[0],
		.events = POLLIN,
	};
	do {
		poll_result = poll(&descriptor, 1,
				   (int)options->redirect_timeout_ms);
	} while (poll_result < 0 && errno == EINTR);

	if (!poll_result) {
		result->timed_out = 1;
		(void)kill(child, SIGKILL);
	} else if (poll_result < 0 ||
		   !(descriptor.revents & (POLLIN | POLLHUP)) ||
		   ghost_read(pipe_fds[0], &observation) != 0) {
		result->error = poll_result < 0 ? errno : EIO;
	}
	close(pipe_fds[0]);

	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited < 0 && !result->error)
		result->error = errno;
	result->child_status = status;
	result->readable = observation.readable;
	result->noreplace_errno = observation.noreplace_errno;
	if (result->readable)
		result->status = POIROT_PROBE_SUSPICIOUS;
	else if (result->timed_out || result->error || !WIFEXITED(status) ||
		 WEXITSTATUS(status))
		result->status = POIROT_PROBE_INCONCLUSIVE;
	else
		result->status = POIROT_PROBE_CLEAN;
	return 0;
}
