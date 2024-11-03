#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/page_ref.h>
#include <linux/pgtable.h>
#include <asm/current.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>

#define DEVICE_NAME "bitflip"
#define N_MINORS 1
#define SIZE_2M 0x200000

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yi-Chi Lee");
MODULE_DESCRIPTION(
	"A module provides a character driver that can flip a bit in page table, creating the vulnerability for attacker to exploit");

static struct cdev bf_dev;
static dev_t dev_num;
static struct class *cls;

static int bitflip_open(struct inode *, struct file *);
static int bitflip_release(struct inode *, struct file *);
static ssize_t bitflip_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t bitflip_write(struct file *, const char __user *, size_t,
			     loff_t *);

static struct file_operations bf_fops = {
	.read = bitflip_read,
	.write = bitflip_write,
	.open = bitflip_open,
	.release = bitflip_release
};

static int __init bitflip_init(void)
{
	int alloc_ret = -1;
	pr_info("bitflip: Initializing the module\n");

	alloc_ret = alloc_chrdev_region(&dev_num, 0, N_MINORS, DEVICE_NAME);
	if (alloc_ret) {
		pr_alert("bitflip: Failed to register device with error = %d\n",
			 alloc_ret);
		return alloc_ret;
	}

	cdev_init(&bf_dev, &bf_fops);
	cdev_add(&bf_dev, dev_num, N_MINORS);
	pr_info("bitflip: Device registered with major number = %d\n", dev_num);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	cls = class_create(THIS_MODULE, DEVICE_NAME);
#else
	cls = class_create(DEVICE_NAME);
#endif
	device_create(cls, NULL, dev_num, NULL, DEVICE_NAME);
	pr_info("bitflip: Device created at /dev/%s\n", DEVICE_NAME);

	return 0;
}

static void __exit bitflip_exit(void)
{
	pr_info("bitflip: Cleaning up the module\n");
	device_destroy(cls, dev_num);
	class_destroy(cls);
	unregister_chrdev_region(dev_num, N_MINORS);
	pr_info("bitflip: Module cleanup completed\n");
}

static int bitflip_open(struct inode *inode, struct file *file)
{
	pr_info("bitflip: Device opened\n");
	return 0;
}

static int bitflip_release(struct inode *inode, struct file *file)
{
	pr_info("bitflip: Device closed\n");
	return 0;
}

static ssize_t bitflip_read(struct file *filp, char __user *buff, size_t len,
			    loff_t *off)
{
	pr_info("bitflip: Read operation is not implemented\n");
	return -EINVAL;
}

static pte_t *vaddr_to_pte(uint64_t address)
{
	pmd_t *pmdp = pmd_off(current->mm, address);
	pr_info("bitflip: [vaddr_to_pte] pmdp: %#llx\n", (uint64_t)pmdp->pmd);
	return pte_offset_map(pmdp, address);
}

static pte_t *vaddr_to_pte_base(uint64_t address)
{
	pmd_t *pmdp = pmd_off(current->mm, address);
	pr_info("bitflip: [to_pte_base] pmdp: %#llx\n", (uint64_t)pmdp->pmd);
	return (pte_t *)pmd_page_vaddr(*pmdp);
}

static ssize_t bitflip_write(struct file *filp, const char __user *buff,
			     size_t len, loff_t *off)
{
	uint64_t user_va1 = (uint64_t)buff;
	uint64_t user_va2 = user_va1 + SIZE_2M;

	struct vm_area_struct *vma = find_vma(current->mm, user_va1);
	pte_t *pte1 = vaddr_to_pte(user_va1); // in the first page table
	pte_t *pte2 = vaddr_to_pte(user_va2); // in the second page table
	pte_t *pte2_4KB = vaddr_to_pte(user_va2 + 0x1000);
	pte_t *pte2_base = vaddr_to_pte_base(user_va2);

	if (pte_present(*pte1)) {
		pte_t *ptr_ptbase = (pte_t *)&pte2_base;

		pr_info("bitflip: pte1 value: %#llx\n", pte_val(*pte1));
		pr_info("bitflip: pte2 value: %#llx\n", pte_val(*pte2));
		pr_info("bitflip: pte2base addr: %#llx\n", (uint64_t)pte2_base);
		pr_info("bitflip: pte2     addr: %#llx\n", (uint64_t)pte2);
		pr_info("bitflip: pte2+4KB addr: %#llx\n", (uint64_t)pte2_4KB);

		pr_info("bitflip: PTRS_PER_PTE: %d\n", PTRS_PER_PTE);
		pr_info("bitflip: pte1     pte_index: %ld\n",
			pte_index(user_va1));
		pr_info("bitflip: pte2     pte_index: %ld\n",
			pte_index(user_va2));
		pr_info("bitflip: pte2_4KB pte_index: %ld\n",
			pte_index(user_va2 + 0x1000));

		// redirect pte1 to the base of the second page table
		set_pte(pte1, pfn_pte(pte_pfn(*ptr_ptbase), PAGE_SHARED));

		flush_cache_page(vma, user_va1, pte_pfn(*pte1));
		flush_tlb_page(vma, user_va1);
		update_mmu_cache(vma, user_va1, pte1);

		pte_unmap(pte1);
		pte_unmap(pte2);
		pte_unmap(pte2_4KB);
	}

	pr_info("bitflip: pte1 value: %#llx\n", pte_val(*pte1));
	pr_info("bitflip: pte2 value: %#llx\n", pte_val(*pte2));
	pr_info("bitflip: pte2base addr: %#llx\n", (uint64_t)pte2_base);
	pr_info("bitflip: pte2     addr: %#llx\n", (uint64_t)pte2);

	pr_info("bitflip: Finished writing to bitflip module\n");
	return pte_index(user_va2);
}

module_init(bitflip_init);
module_exit(bitflip_exit);
