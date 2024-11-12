#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <elf.h>

#define BITFLIP_MAGIC 0xF5
#define IOCTL_FLIP_BIT _IOW(BITFLIP_MAGIC, 0, unsigned long)

struct bitflip_args {
	unsigned long vaddr;
	pid_t pid;
};

void get_text_section_address(pid_t pid, unsigned long *text_start,
			      unsigned long *text_end)
{
	char path[256];
	snprintf(path, sizeof(path), "/proc/%d/maps", pid);

	FILE *maps_file = fopen(path, "r");
	if (maps_file == NULL) {
		perror("Failed to open /proc/[pid]/maps");
		return;
	}

	char line[256];
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
				*text_start = start;
				*text_end = end;
				break;
			}
		}
	}
	fclose(maps_file);

	unsigned long main_offset;
	int fd = open("/usr/local/bin/mysudo", O_RDONLY);
	if (fd == -1) {
		perror("Failed to open /usr/local/bin/mysudo");
		return;
	}

	Elf64_Ehdr ehdr;
	if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
		perror("Failed to read ELF header");
		close(fd);
		return;
	}

	Elf64_Shdr shdr;
	for (int i = 0; i < ehdr.e_shnum; i++) {
		lseek(fd, ehdr.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET);
		if (read(fd, &shdr, sizeof(shdr)) != sizeof(shdr)) {
			perror("Failed to read section header");
			close(fd);
			return;
		}

		if (shdr.sh_type == SHT_SYMTAB) {
			Elf64_Sym *symtab = malloc(shdr.sh_size);
			lseek(fd, shdr.sh_offset, SEEK_SET);
			if (read(fd, symtab, shdr.sh_size) != shdr.sh_size) {
				perror("Failed to read symbol table");
				goto leave_symtab;
			}

			Elf64_Shdr str_shdr;
			lseek(fd,
			      ehdr.e_shoff + shdr.sh_link * sizeof(Elf64_Shdr),
			      SEEK_SET);
			if (read(fd, &str_shdr, sizeof(str_shdr)) !=
			    sizeof(str_shdr)) {
				perror("Failed to read string table header");
				goto leave_symtab;
			}

			char *strtab = malloc(str_shdr.sh_size);
			lseek(fd, str_shdr.sh_offset, SEEK_SET);
			if (read(fd, strtab, str_shdr.sh_size) !=
			    str_shdr.sh_size) {
				perror("Failed to read string table");
				goto leave_symtab_free_strtab;
			}

			for (int j = 0; j < shdr.sh_size / sizeof(Elf64_Sym);
			     j++) {
				if (symtab[j].st_name != 0) {
					char *symbol_name =
						&strtab[symtab[j].st_name];
					if (strcmp(symbol_name, "main") == 0) {
						printf("Found 'main' at address: %#lx\n",
						       symtab[j].st_value);
						main_offset =
							symtab[j].st_value;
						goto leave;
					}
				}
			}

leave_symtab_free_strtab:
			free(strtab);
leave_symtab:
			free(symtab);
			close(fd);
			return;
leave:
			break;
		}
	}

	close(fd);

	*text_start += main_offset;
	printf("main: %#lx", main_offset);
	printf("Adjusted text_start to main function: 0x%lx\n", *text_start);
}

unsigned long find_target_address(pid_t pid, unsigned long text_start,
				  unsigned long text_end)
{
	unsigned long address = text_start;
	unsigned instruction;

	while (address < text_end) {
		errno = 0;
		instruction =
			ptrace(PTRACE_PEEKTEXT, pid, (void *)address, NULL);
		if (errno) {
			perror("PTRACE_PEEKTEXT failed");
			break;
		}

		if (instruction == 0)
			goto next;

		// printf("Instruction at %#lx: %#x\n", address, instruction);

		// Check for 'bl' (branch with link) instruction pattern (0x97xxxxxx in ARMv8)
		if ((instruction & 0xFF000000) == 0x97000000) {
			unsigned long next_address = address + sizeof(unsigned);
			unsigned next_instruction = ptrace(PTRACE_PEEKTEXT, pid,
							   (void *)next_address,
							   NULL);
			if (next_instruction == 0)
				goto next;

			// Check for 'cmp' instruction (0x7100001f is 'cmp w0, #0x0' in ARMv8)
			if ((next_instruction & 0xFF000000) != 0x71000000)
				goto next;

			unsigned long next2_address =
				next_address +
				sizeof(unsigned); // Move to next instruction
			unsigned next2_instruction =
				ptrace(PTRACE_PEEKTEXT, pid,
				       (void *)next2_address, NULL);
			if (next2_instruction == 0)
				goto next;

			// Check for 'b.ne' instruction (0x54000181 is 'b.ne' in ARMv8)
			if ((next2_instruction & 0xFF000000) == 0x54000000) {
				printf("Found 'bl' at %#lx, 'cmp' at %#lx, and 'b.ne' at %#lx\n",
				       address, next_address, next2_address);
				return address;
			}
		}

next:
		address += sizeof(unsigned);
	}

	return 0; // Not found
}

int main(int argc, char *argv[])
{
	pid_t pid = fork();
	if (pid == 0) {
		// Child process: Execute mysudo
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
			perror("PTRACE_TRACEME failed\n");
		}
		execl("/usr/local/bin/mysudo", "/usr/local/bin/mysudo",
		      "../test/test-exe", NULL);
		perror("execl failed");
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		// Parent process
		int wait_status;
		waitpid(pid, &wait_status, 0);
		ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

		unsigned long text_start, text_end;
		get_text_section_address(pid, &text_start, &text_end);

		unsigned long target_addr =
			find_target_address(pid, text_start, text_end);
		printf("target: %#lx\n", target_addr);

		ptrace(PTRACE_DETACH, pid, NULL, NULL); // Detach when done
		waitpid(pid, NULL, 0);
	} else {
		perror("fork failed");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
