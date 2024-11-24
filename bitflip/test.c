#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdint.h>

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

	FILE *maps_file = fopen("/proc/self/maps", "r");
	if (maps_file == NULL) {
		perror("Failed to open /proc/[pid]/maps");
		return;
	}

	char line[256];
	unsigned long text_start, text_end;
	while (fgets(line, sizeof(line), maps_file)) {
		unsigned long start, end;
		char perms[5], offset[9], dev[6], inode[11], pathname[256];

		printf("%s", line);

		// Parse the line
		if (sscanf(line, "%lx-%lx %4s %8s %5s %10s %s", &start, &end,
			   perms, offset, dev, inode, pathname) == 7) {
			if (strchr(perms, 'x')) {
				printf("Text section found at address range: 0x%lx - 0x%lx\n",
				       start, end);
				text_start = start;
				text_end = end;
				break;
			}
		}
	}
	// text_start = 0xaaaaaaaa0000;
	fclose(maps_file);
	printf("text_start+c78: %#lx\n", text_start+0xc78);
	printf("text_end: %#lx\n", text_end);

	// text_start += 0xc78;

	printf("text_start's value: %#lx\n", *(uint64_t *)text_start);

	unsigned long vaddr = (unsigned long)block;

	fd = open("/dev/bitflip", O_RDWR);
	if (fd < 0) {
		perror("Failed to open the device");
		exit(EXIT_FAILURE);
	}

	struct bitflip_args arg = {
		.vaddr = text_start,
		.pid = getpid(),
		.target_bit = 5,
		.pfn_shift = 0,
	};

	printf("value: %#lx\n", *(unsigned long *)block);

	printf("[bitflip] vaddr: %#lx, pid: %d, target_bit: %d\n", arg.vaddr, arg.pid, arg.target_bit);

	if (ioctl(fd, IOCTL_FLIP_BIT, &arg) == -1) {
		perror("ioctl failed");
		close(fd);
		exit(EXIT_FAILURE);
	}

	printf("value: %#lx\n", *(unsigned long *)block);

	printf("text_start's value: %#lx\n", *(uint64_t *)text_start);

	printf("Bit flip operation completed\n");
	close(fd);
	return 0;
}
