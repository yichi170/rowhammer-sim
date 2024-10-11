#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/version.h>

#define DEVICE_NAME "bitflip"
#define N_MINORS 1

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yi-Chi Lee");

static struct cdev bf_dev;
static dev_t dev_num;
static struct class *cls;

static int bitflip_open(struct inode *, struct file *);
static int bitflip_release(struct inode *, struct file *);
static ssize_t bitflip_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t bitflip_write(struct file *, const char __user *, size_t, loff_t *);

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
		pr_alert("bitflip: Failed to register device with error = %d\n", alloc_ret);
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

static ssize_t bitflip_read(struct file *filp, char __user *buff,
			    size_t len, loff_t *off)
{
	pr_info("bitflip: Read operation is not implemented\n");
	return -EINVAL;
}

static ssize_t bitflip_write(struct file *filp, const char __user *buff,
			     size_t len, loff_t *off)
{
	pr_info("bitflip: Write operation is not implemented\n");
	return -EINVAL;
}

module_init(bitflip_init);
module_exit(bitflip_exit);
