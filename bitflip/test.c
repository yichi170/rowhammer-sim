#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#define BITFLIP_MAGIC 0xF5
#define IOCTL_FLIP_BIT _IOW(BITFLIP_MAGIC, 0, unsigned long)

#define SIZE_MB 0x100000 // 1024 * 1024

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

	if (ioctl(fd, IOCTL_FLIP_BIT, vaddr) == -1) {
		perror("ioctl failed");
		close(fd);
		exit(EXIT_FAILURE);
	}

	printf("Bit flip operation completed\n");
	close(fd);
	return 0;
}
