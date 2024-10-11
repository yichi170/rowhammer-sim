#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#define SIZE_4M 4 * 1024 * 1024

int main()
{
	/* allocate 4MB for having two page tables */
	void *block = mmap(NULL, SIZE_4M, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (block == MAP_FAILED) {
		perror("mmap a block failed");
		exit(EXIT_FAILURE);
	}

	uint64_t vaddr = (uint64_t)block;
	printf("block's vaddr: %#10lx\n", (size_t)block);

	/* interact with kernel module */
	int fd = open("/dev/bitflip", O_RDWR);
	if (fd == -1) {
		perror("failed to open /dev/bitflip");
		munmap(block, SIZE_4M);
		exit(EXIT_FAILURE);
	}

	if (write(fd, block, sizeof(uint64_t)) == sizeof(uint64_t)) {
		perror("failed to write address to /dev/bitflip");
	}

	if (close(fd) == 0) {
		perror("failed to close /dev/bitflip");
	}

	/* free memory chunk */
	if (munmap(block, SIZE_4M) == -1) {
		printf("failed to free memory block\n");
	}

	return 0;
}
