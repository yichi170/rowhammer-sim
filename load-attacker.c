#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <assert.h>
#include <sys/ioctl.h>

#define BITFLIP_MAGIC 0xF5
#define IOCTL_FLIP_BIT _IOW(BITFLIP_MAGIC, 0, unsigned long)

struct bitflip_args {
	unsigned long vaddr;
	pid_t pid;
	int target_bit;
	int pfn_shift;
};

typedef struct elf_s {
	char *filename;
	Elf64_Ehdr ehdr;
	Elf64_Phdr *phdrs;
	uint64_t text_start;
	uint64_t text_size;
	int fd;
} elf_t;

void err_quit(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

static size_t count_arg(char **args)
{
	int argc = 0;
	for (char **arg = args; *arg != NULL; ++arg) {
		argc++;
	}
	return argc;
}

elf_t *parse_elf_headers(const char *elf_file)
{
	elf_t *elf = malloc(sizeof(elf_t));
	elf->fd = open(elf_file, O_RDONLY);
	if (elf->fd == -1) {
		err_quit("Open ELF format file");
	}

	elf->filename = malloc(strlen(elf_file) + 1);
	strcpy(elf->filename, elf_file);

	Elf64_Ehdr *ehdr = &elf->ehdr;
	if (read(elf->fd, ehdr, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
		close(elf->fd);
		err_quit("Read ELF header");
	}

	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
		err_quit("This file is not in ELF format");
	}

	elf->phdrs = malloc(ehdr->e_phentsize * ehdr->e_phnum);
	Elf64_Phdr *phdrs = elf->phdrs;

	if (!phdrs) {
		close(elf->fd);
		err_quit("Memory allocation for program headers");
	}

	lseek(elf->fd, ehdr->e_phoff, SEEK_SET);
	if (read(elf->fd, phdrs, ehdr->e_phentsize * ehdr->e_phnum) !=
	    ehdr->e_phentsize * ehdr->e_phnum) {
		free(phdrs);
		close(elf->fd);
		err_quit("Reading program headers");
	}

	return elf;
}

char *setup_stack(elf_t *elf, char **argv, char **envp)
{
	size_t argc = count_arg(argv);
	size_t envc = count_arg(envp);
	const int STACK_SIZE = 0x800000; // 8MB
	char *stack_top;
	char *stack_ptr;

	stack_top = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (stack_top == MAP_FAILED) {
		err_quit("Failed to allocate memory for the stack");
	}

	stack_ptr = stack_top + STACK_SIZE;
	stack_ptr = (char *)((uintptr_t)stack_ptr & ~0xF);

	Elf64_auxv_t *auxp = (Elf64_auxv_t *)(envp + envc + 1);
	int auxc = 0;
	while (1) {
		stack_ptr -= sizeof(Elf64_auxv_t);
		auxc++;

		// ensure AT_NULL will be copied to the stack
		if (auxp->a_type == AT_NULL) {
			break;
		}
		auxp++;
	}
	auxp = (Elf64_auxv_t *)(envp + envc + 1);
	memcpy(stack_ptr, auxp, sizeof(Elf64_auxv_t) * auxc);

	Elf64_auxv_t *stk_auxp = (Elf64_auxv_t *)stack_ptr;
	while (stk_auxp->a_type != AT_NULL) {
		if (stk_auxp->a_type == AT_PHDR) {
			stk_auxp->a_un.a_val = (uint64_t)elf->phdrs;
		} else if (stk_auxp->a_type == AT_PHNUM) {
			stk_auxp->a_un.a_val = elf->ehdr.e_phnum;
		} else if (stk_auxp->a_type == AT_BASE) {
			stk_auxp->a_un.a_val = 0;
		} else if (stk_auxp->a_type == AT_ENTRY) {
			stk_auxp->a_un.a_val = elf->ehdr.e_entry;
		} else if (stk_auxp->a_type == AT_EXECFN) {
			stk_auxp->a_un.a_val = (uint64_t)elf->filename;
		}
		stk_auxp++;
	}

	stack_ptr -= sizeof(char *) * (envc + 1);
	char **envp_stack = (char **)stack_ptr;
	memcpy(envp_stack, envp, sizeof(char *) * (envc + 1));

	stack_ptr -= sizeof(char *) * (argc + 1);
	char **argv_stack = (char **)stack_ptr;
	memcpy(argv_stack, argv, sizeof(char *) * (argc + 1));

	stack_ptr -= sizeof(size_t);
	*stack_ptr = argc;

	return stack_ptr;
}

void jump_exec(char *stack, void *entry)
{
	printf("jump to entry point: %#lx\n", (uintptr_t)entry);

	__asm__ volatile("mov x2, #0\n"
			 "mov x3, #0\n"
			 "mov x4, #0\n"
			 "mov x5, #0\n"
			 "mov x6, #0\n"
			 "mov x7, #0\n"
			 "mov sp, %0\n"
			 "br %1\n"
			 :
			 : "r"(stack), "r"(entry));

	err_quit("Should not reach here");
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "USAGE: %s <program to load>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	char *program = argv[1];
	printf("target program %s\n", program);
	elf_t *elf = parse_elf_headers(program);

	for (int i = 0; i < elf->ehdr.e_phnum; i++) {
		Elf64_Phdr *phdr = &elf->phdrs[i];
		if (phdr->p_type == PT_LOAD) {
			void *segment_vaddr = (void *)phdr->p_vaddr;
			size_t segment_size = phdr->p_memsz;
			size_t segment_file_size = phdr->p_filesz;
			uint64_t shifted_vaddr = phdr->p_vaddr & ~0xFFF;

			uint64_t padding_size = phdr->p_vaddr - shifted_vaddr;
			printf("==============================\n");
			printf("padding size: %#lx\n", padding_size);

			void *mapped_mem =
				mmap((void *)shifted_vaddr,
				     segment_size + padding_size,
				     PROT_READ | PROT_WRITE | PROT_EXEC,
				     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

			if (mapped_mem == MAP_FAILED) {
				free(elf);
				err_quit(
					"mmap failed to allocate memory for segment");
			}

			void *mapped_ptr =
				(void *)((uint64_t)mapped_mem + padding_size);

			assert((uint64_t)mapped_mem == shifted_vaddr);

			lseek(elf->fd, phdr->p_offset, SEEK_SET);
			if (read(elf->fd, mapped_ptr, segment_file_size) !=
			    segment_file_size) {
				free(elf);
				err_quit("Load segment to memory");
			}

			// zero-out the remaining segment space (.bss section)
			if (segment_size > segment_file_size) {
				memset((char *)mapped_ptr + segment_file_size,
				       0, segment_size - segment_file_size);
			}

			if ((phdr->p_flags & PF_R) && (phdr->p_flags & PF_X)) {
				elf->text_size = segment_size;
				elf->text_start = phdr->p_vaddr;
			}

			printf("segment_flags [r/w/x]: %c%c%c\n",
			       " r"[(phdr->p_flags & PF_R) != 0],
			       " w"[(phdr->p_flags & PF_W) != 0],
			       " x"[(phdr->p_flags & PF_X) != 0]);
			printf("segment vaddr specified in ELF: %#lx\n",
			       (uint64_t)segment_vaddr);
			printf("shifted segment vaddr: %#lx\n",
			       (uint64_t)shifted_vaddr);
			printf("writing data from this addr: %#lx\n",
			       (uint64_t)mapped_ptr);
			printf("segment mapped to this region: %#lx - %#lx\n",
			       (uint64_t)mapped_mem,
			       (uint64_t)mapped_mem + segment_size +
				       padding_size);
			printf("==============================\n");
		}
	}

	char *stack = setup_stack(elf, argv + 1, envp);
	uint64_t target_addr;

	for (unsigned *addr = (unsigned *)elf->ehdr.e_entry;
	     (uint64_t)addr < elf->text_start + elf->text_size; addr++) {
		unsigned instr = *addr;
		if ((instr & 0xFF000000) == 0x97000000) {
			unsigned *next_addr = addr + 1;
			unsigned next_instr = *next_addr;

			// Check for 'cmp' instr (0x7100001f is 'cmp w0, #0x0' in ARMv8)
			if ((next_instr & 0xFF000000) != 0x71000000)
				continue;

			unsigned *next2_addr = next_addr + 1;
			unsigned next2_instr = *next2_addr;

			// Check for 'b.ne' instr (0x54000181 is 'b.ne' in ARMv8)
			if ((next2_instr & 0xFF000000) == 0x54000000) {
				printf("Found 'bl' at %#lx, 'cmp' at %#lx, and 'b.ne' at %#lx\n",
				       (uint64_t)addr, (uint64_t)next_addr,
				       (uint64_t)next2_addr);
				printf("instruction 1: %#x\n", instr);
				printf("instruction 2: %#x\n", next_instr);
				printf("instruction 3: %#x\n", next2_instr);
				target_addr = (uint64_t)next_addr;
				break;
			}
		}
	}

	int fd = open("/dev/bitflip", O_RDWR);
	if (fd < 0) {
		perror("Failed to open the device");
		exit(EXIT_FAILURE);
	}

	struct bitflip_args arg = {
		.vaddr = target_addr,
		.pid = getpid(),
		.target_bit = 5,
		.pfn_shift = 0,
	};
	if (ioctl(fd, IOCTL_FLIP_BIT, &arg) == -1) {
		perror("ioctl failed");
		close(fd);
		exit(EXIT_FAILURE);
	}

	jump_exec(stack, (void *)elf->ehdr.e_entry);
}