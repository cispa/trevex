#include "dss-victim.h"
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/uaccess.h>

MODULE_AUTHOR("CISPA RootSec Group");
MODULE_DESCRIPTION("FP-DSS Victim Module");
MODULE_LICENSE("GPL");

#define TAG "[fpdss-victim] "

#define INTELASM(code) ".intel_syntax noprefix\n\t" code "\n\t.att_syntax prefix\n"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define from_user raw_copy_from_user
#define to_user raw_copy_to_user
#else
#define from_user copy_from_user
#define to_user copy_to_user
#endif

static int device_open(struct inode *inode, struct file *file) {
  /* Lock module */
  try_module_get(THIS_MODULE);
  return 0;
}

static int device_release(struct inode *inode, struct file *file) {
  /* Unlock module */
  module_put(THIS_MODULE);
  return 0;
}

__attribute__((naked))
void divider_victim_raw(size_t value) {
  asm volatile(INTELASM(
    // save xmm1
    "movq rax, xmm1\n\t"
    "push rax\n\t" // low 64b xmm1
    "pextrq rax, xmm1, 1\n\t"
    "push rax\n\t" // high 64b xmm1

    // save xmm0
    "movq rax, xmm0\n\t"
    "push rax\n\t" // low 64b xmm0
    "pextrq rax, xmm0, 1\n\t"
    "push rax\n\t" // high 64b xmm0

    // prep div args
    "movq xmm2, rdi\n\t" // xmm2 -> first arg
    //"movabs    rdi, 0x4444444444444444\n\t"
    "movq xmm2, rdi\n\t" // xmm2 -> first arg
    "mov rdi, 0x1\n\t"
    "movq xmm1, rdi\n\t" // xmm1 -> 0x1

    // actually do the division
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"
    "divsd  xmm1, xmm2\n\t"

    "pop rax\n\t" // high 64b xmm0
    "pinsrq xmm0, rax, 1\n\t"
    "pop rax\n\t" // low 64b xmm0
    "pinsrq xmm0, rax, 0\n\t"

    "pop rax\n\t" // high 64b xmm1
    "pinsrq xmm1, rax, 1\n\t"
    "pop rax\n\t" // low 64b xmm1
    "pinsrq xmm1, rax, 0\n\t"
    "ret\n\t"
  ) :: : "memory");
}

void static divider_victim(size_t value) {
  //printk(KERN_INFO TAG "Victim called with value %llx\n", value);
  divider_victim_raw(value);
}

static long device_ioctl(struct file *file, unsigned int ioctl_num,
                         unsigned long ioctl_param) {

  size_t val;
  from_user(&val, (void *)ioctl_param, sizeof(val));
  divider_victim(val);

  return 0;
}

static struct file_operations f_ops = {.unlocked_ioctl = device_ioctl,
                                       .open = device_open,
                                       .release = device_release};

static struct miscdevice misc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = MODULE_DEVICE_NAME,
    .fops = &f_ops,
    .mode = S_IRWXUGO,
};

int init_module(void) {
  int r;

  /* Register device */
  r = misc_register(&misc_dev);
  if (r != 0) {
    printk(KERN_ALERT TAG "Failed registering device with %d\n", r);
    return 1;
  }

  printk(KERN_INFO TAG "Loaded.\n");
  return 0;
}

void cleanup_module(void) {
  misc_deregister(&misc_dev);
  printk(KERN_INFO TAG "Removed.\n");
}
