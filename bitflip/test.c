#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#define BITFLIP_MAGIC 0xF5
#define IOCTL_FLIP_BIT _IOW(BITFLIP_MAGIC, 0, unsigned long)

#define SIZE_MB 0x100000 // 1024 * 1024

struct bitflip_args {
	unsigned long vaddr;
	pid_t pid;
	int target_bit;
	int pfn_shift;
};

int main()
{
	int fd;
	void *block = mmap(NULL, SIZE_MB, PROT_WRITE,
			   MAP_PRIVATE | MAP_ANON | MAP_POPULATE, -1, 0);

	if (block == MAP_FAILED) {
		perror("mmap 1MB");
		exit(EXIT_FAILURE);
	}

	unsigned long vaddr = (unsigned long)block;

	fd = open("/dev/bitflip", O_RDWR);
	if (fd < 0) {
		perror("Failed to open the device");
		exit(EXIT_FAILURE);
	}

	struct bitflip_args arg = {
		.vaddr = vaddr,
		.pid = getpid(),
		.target_bit = 5,
		.pfn_shift = 0,
	};

	printf("value: %#lx\n", *(unsigned long *)block);

	printf("vaddr: %#lx, pid: %d\n", vaddr, getpid());

	if (ioctl(fd, IOCTL_FLIP_BIT, &arg) == -1) {
		perror("ioctl failed");
		close(fd);
		exit(EXIT_FAILURE);
	}

	printf("value: %#lx\n", *(unsigned long *)block);

	printf("Bit flip operation completed\n");
	close(fd);
	return 0;
}
