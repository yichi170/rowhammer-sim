#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/uaccess.h>
#include <linux/sched.h>

#define DEVICE_NAME "bitflip"
#define N_MINORS 1
#define BITFLIP_MAGIC 0xF5
#define IOCTL_FLIP_BIT _IOW(BITFLIP_MAGIC, 0, unsigned long)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yi-Chi Lee");
MODULE_DESCRIPTION(
	"A module provides a character driver that can flip a bit in page table, creating the vulnerability for attacker to exploit");

static struct cdev bf_dev;
static dev_t dev_num;
static struct class *cls;

static int bitflip_core_op(unsigned long, pid_t);
static long bitflip_ioctl(struct file *, unsigned int, unsigned long);

static struct file_operations bf_fops = { .unlocked_ioctl = bitflip_ioctl };

struct bitflip_args {
	unsigned long vaddr;
	pid_t pid;
};

static int __init bitflip_init(void)
{
	int alloc_ret = -1;
	pr_info("[bitflip] Initializing the module\n");

	alloc_ret = alloc_chrdev_region(&dev_num, 0, N_MINORS, DEVICE_NAME);
	if (alloc_ret) {
		pr_alert(
			"[bitflip] Failed to register device with error = %d\n",
			alloc_ret);
		return alloc_ret;
	}

	cdev_init(&bf_dev, &bf_fops);
	cdev_add(&bf_dev, dev_num, N_MINORS);
	pr_info("[bitflip] Device registered with major number = %d\n",
		dev_num);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	cls = class_create(THIS_MODULE, DEVICE_NAME);
#else
	cls = class_create(DEVICE_NAME);
#endif
	device_create(cls, NULL, dev_num, NULL, DEVICE_NAME);
	pr_info("[bitflip] Device created at /dev/%s\n", DEVICE_NAME);

	return 0;
}

static void __exit bitflip_exit(void)
{
	pr_info("[bitflip] Cleaning up the module\n");
	device_destroy(cls, dev_num);
	class_destroy(cls);
	unregister_chrdev_region(dev_num, N_MINORS);
	pr_info("[bitflip] Module cleanup completed\n");
}

static long bitflip_ioctl(struct file *, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case IOCTL_FLIP_BIT: {
		struct bitflip_args user_args;
		int ret;

		if (copy_from_user(&user_args,
				   (struct bitflip_args __user *)arg,
				   sizeof(struct bitflip_args))) {
			return -EFAULT;
		}
		pr_info("[ioctl] vaddr: %#lx, pid: %d\n", user_args.vaddr,
			user_args.pid);
		ret = bitflip_core_op(user_args.vaddr, user_args.pid);
		if (ret)
			return ret;
		break;
	}
	default:
		return -EINVAL;
	}
	return 0;
}

static int bitflip_core_op(unsigned long vaddr, pid_t pid)
{
	pmd_t *pmdp;
	pte_t *ptep;
	unsigned long pfn;
	struct page *page;
	struct task_struct *task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);

	pr_info("[bitflip] vaddr: %#lx\n", vaddr);

	pmdp = pmd_off(task->mm, vaddr);
	ptep = pte_offset_map(pmdp, vaddr);
	pfn = pte_pfn(*ptep);
	pte_unmap(ptep);

	pr_info("[bitflip] pfn = %ld\n", pfn);
	pr_info("[bitflip] page's phys addr = %#llx\n", __pfn_to_phys(pfn));

	pfn += 4;

	pr_info("[bitflip] pfn+4 = %ld\n", pfn);
	pr_info("[bitflip] next page's phys addr: %#llx\n", __pfn_to_phys(pfn));

	page = pfn_to_page(pfn);

	if (page) {
		void *vaddr;
		vaddr = kmap(page);
		*(uint64_t *)vaddr ^= (1 << 16);
		kunmap(page);
	}

	pr_info("[bitflip] Successfully flipped a bit in physical memory.\n");

	return 0;
}

module_init(bitflip_init);
module_exit(bitflip_exit);
