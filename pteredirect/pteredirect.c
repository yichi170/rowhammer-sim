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

#define DEVICE_NAME "pteredirect"
#define N_MINORS 1
#define SIZE_2M 0x200000

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yi-Chi Lee");
MODULE_DESCRIPTION(
	"A module provides a character driver that can flip a bit in page table, creating the vulnerability for attacker to exploit");

static struct cdev bf_dev;
static dev_t dev_num;
static struct class *cls;

static int pteredirect_open(struct inode *, struct file *);
static int pteredirect_release(struct inode *, struct file *);
static ssize_t pteredirect_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t pteredirect_write(struct file *, const char __user *, size_t,
			     loff_t *);

static struct file_operations bf_fops = {
	.read = pteredirect_read,
	.write = pteredirect_write,
	.open = pteredirect_open,
	.release = pteredirect_release
};

static int __init pteredirect_init(void)
{
	int alloc_ret = -1;
	pr_info("pteredirect: Initializing the module\n");

	alloc_ret = alloc_chrdev_region(&dev_num, 0, N_MINORS, DEVICE_NAME);
	if (alloc_ret) {
		pr_alert("pteredirect: Failed to register device with error = %d\n",
			 alloc_ret);
		return alloc_ret;
	}

	cdev_init(&bf_dev, &bf_fops);
	cdev_add(&bf_dev, dev_num, N_MINORS);
	pr_info("pteredirect: Device registered with major number = %d\n", dev_num);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	cls = class_create(THIS_MODULE, DEVICE_NAME);
#else
	cls = class_create(DEVICE_NAME);
#endif
	device_create(cls, NULL, dev_num, NULL, DEVICE_NAME);
	pr_info("pteredirect: Device created at /dev/%s\n", DEVICE_NAME);

	return 0;
}

static void __exit pteredirect_exit(void)
{
	pr_info("pteredirect: Cleaning up the module\n");
	device_destroy(cls, dev_num);
	class_destroy(cls);
	unregister_chrdev_region(dev_num, N_MINORS);
	pr_info("pteredirect: Module cleanup completed\n");
}

static int pteredirect_open(struct inode *inode, struct file *file)
{
	pr_info("pteredirect: Device opened\n");
	return 0;
}

static int pteredirect_release(struct inode *inode, struct file *file)
{
	pr_info("pteredirect: Device closed\n");
	return 0;
}

static ssize_t pteredirect_read(struct file *filp, char __user *buff, size_t len,
			    loff_t *off)
{
	pr_info("pteredirect: Read operation is not implemented\n");
	return -EINVAL;
}

static pte_t *vaddr_to_pte(uint64_t address)
{
	pmd_t *pmdp = pmd_off(current->mm, address);
	pr_info("pteredirect: [vaddr_to_pte] pmdp: %#llx\n", (uint64_t)pmdp->pmd);
	return pte_offset_map(pmdp, address);
}

static pte_t *vaddr_to_pte_base(uint64_t address)
{
	pmd_t *pmdp = pmd_off(current->mm, address);
	pr_info("pteredirect: [to_pte_base] pmdp: %#llx\n", (uint64_t)pmdp->pmd);
	return (pte_t *)pmd_page_vaddr(*pmdp);
}

static ssize_t pteredirect_write(struct file *filp, const char __user *buff,
			     size_t len, loff_t *off)
{
	uint64_t user_va1 = (uint64_t)buff;
	uint64_t user_va2 = user_va1 + SIZE_2M;

	struct vm_area_struct *vma = find_vma(current->mm, user_va1);
	pte_t *ptep1 = vaddr_to_pte(user_va1); // in the first page table
	pte_t *ptep2 = vaddr_to_pte(user_va2); // in the second page table
	pte_t *pte2_base = vaddr_to_pte_base(user_va2);
	unsigned long pfn_pte2 =
		page_to_pfn(pmd_page(*pmd_off(current->mm, user_va2)));

	if (pte_present(*ptep1)) {
		unsigned long pfn;
		pgprot_t old_prot;

		pr_info("pteredirect: Old ptep1 present: %d writable: %d user exec: %d dirty: %d young: %d\n",
			pte_present(*ptep1), pte_write(*ptep1),
			pte_user_exec(*ptep1), pte_dirty(*ptep1),
			pte_young(*ptep1));
		pr_info("pteredirect: ptep1 value: %#llx\n", pte_val(*ptep1));
		pr_info("pteredirect: ptep2 value: %#llx\n", pte_val(*ptep2));
		pr_info("pteredirect: pte2base addr: %#llx\n", (uint64_t)pte2_base);
		pr_info("pteredirect: ptep2    addr: %#llx\n", (uint64_t)ptep2);

		pr_info("pteredirect: PTRS_PER_PTE: %d\n", PTRS_PER_PTE);
		pr_info("pteredirect: ptep1    pte_index: %ld\n",
			pte_index(user_va1));
		pr_info("pteredirect: ptep2    pte_index: %ld\n",
			pte_index(user_va2));

		// redirect ptep1 to the base of the second page table
		pfn = pte_pfn(*ptep1);
		old_prot = __pgprot(pte_val(pfn_pte(pfn, __pgprot(0))) ^
				    pte_val(*ptep1));
		set_pte(ptep1, pfn_pte(pfn_pte2, old_prot));

		// ensure cache and TLB are in sync
		flush_cache_page(vma, user_va1, pte_pfn(*ptep1));
		flush_tlb_page(vma, user_va1);
		update_mmu_cache(vma, user_va1, ptep1);

		pr_info("pteredirect: ptep1 new value: %#llx\n", pte_val(*ptep1));
		pr_info("pteredirect: New ptep1 present: %d writable: %d user exec: %d dirty: %d young: %d\n",
			pte_present(*ptep1), pte_write(*ptep1),
			pte_user_exec(*ptep1), pte_dirty(*ptep1),
			pte_young(*ptep1));

		pte_unmap(ptep1);
		pte_unmap(ptep2);
	}

	pr_info("pteredirect: Finished writing to pteredirect module\n");
	return pte_index(user_va2);
}

module_init(pteredirect_init);
module_exit(pteredirect_exit);
