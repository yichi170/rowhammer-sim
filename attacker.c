#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#define SIZE_MB 0x100000 // 1024 * 1024
#define SIZE_GB 0x40000000
#define SIZE_4GB 0x100000000

int main()
{
	/* allocate 4MB for having two page tables */
	void *block = mmap(NULL, 4 * SIZE_MB, PROT_WRITE,
			   MAP_PRIVATE | MAP_ANON | MAP_POPULATE, -1, 0);
	if (block == MAP_FAILED) {
		perror("mmap 4MB");
		exit(EXIT_FAILURE);
	}

	uint64_t vaddr = (uint64_t)block;
	uint64_t vaddr1 = vaddr;
	uint64_t vaddr2 = vaddr + 2 * SIZE_MB;
	*((int *)vaddr1) = 1;
	*((int *)vaddr2) = 2;

	printf("block's vaddr: %#lx\n", (size_t)block);
	printf("vaddr2's val: %d\n", *(int *)vaddr2);
	printf("vaddr1's val: %d\n", *(int *)vaddr1);

	/* interact with kernel module */
	int fd = open("/dev/bitflip", O_RDWR);
	if (fd == -1) {
		perror("open /dev/bitflip");
		munmap(block, 4 * SIZE_MB);
		exit(EXIT_FAILURE);
	}

	if (write(fd, block, sizeof(uint64_t)) != sizeof(uint64_t)) {
		perror("write address to /dev/bitflip");
	}

	printf("vaddr2's val: %d\n", *(int *)vaddr2);
	printf("vaddr1's val: %#lx\n", *(uint64_t *)vaddr1);

	if (close(fd) != 0) {
		perror("close /dev/bitflip");
	}

	if (munmap(block, 4 * SIZE_MB) == -1) {
		printf("failed to free memory block\n");
	}

	return 0;
}
