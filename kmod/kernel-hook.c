#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/utsname.h>
#include <asm/current.h>
// current->pid

#define USE_HARDCODED_SYSCALL_ADDR 0

MODULE_AUTHOR("Tomoya KABE");
MODULE_LICENSE("GPL");

/* original syscall functions' pointer */
#if !USE_HARDCODED_SYSCALL_ADDR
asmlinkage int (*orig_open)(const char *pathname, int flags);
asmlinkage int (*orig_close)(int fd);
asmlinkage int (*orig_read)(int fd, void* buf, size_t count);
asmlinkage int (*orig_write)(int fd, const void* buf, size_t count);
#endif

#if USE_HARDCODED_SYSCALL_ADDR
int (*orig_open)(const char* pathname, int flags) = 0xffffffff810ed242;
int (*orig_close)(int fd) =0xffffffff810ed071;
int (*orig_read)(int fd, void* buf, size_t count) = 0xffffffff810ef5e0;
int (*orig_write)(int fd, const void* buf, size_t count) = 0xffffffff810ef3fc;
#endif

static int changed_syscall_ptr = 0;

unsigned long **find_sys_call_table(void);
//asmlinkage int (*sys_call_table)[];
unsigned long** sys_call_table;

asmlinkage static int hook_open(const char *pathname, int flags)
{
    printk(KERN_INFO "hook_open(\"%s\", %d)\n", pathname, flags);
    return orig_open(pathname, flags);
}

asmlinkage static int hook_close(int fd)
{
    printk(KERN_INFO "hook_close(%d)\n", fd);
    return orig_close(fd);
}

asmlinkage static int hook_read(int fd, void* buf, size_t count)
{
    printk(KERN_INFO "hook_read(%d, %ld, \"%s\")\n", fd, count, (char*)buf);
    return orig_read(fd, buf, count);
}

asmlinkage static int hook_write(int fd, const void* buf, size_t count)
{
    printk(KERN_INFO "hook_write(%d, %ld, \"%s\")\n", fd, count, (char*)buf);
    return orig_write(fd, buf, count);
}

//static int hook_init(void){
int init_module() {
    printk(KERN_INFO "hook_init\n");
#if !USE_HARDCODED_SYSCALL_ADDR
    sys_call_table = find_sys_call_table();
    if(sys_call_table == NULL) {
        printk(KERN_INFO "Can't find syscall table\n");
        return -2;
    }
    return -1;
    orig_open = sys_call_table[__NR_open];
    orig_close = sys_call_table[__NR_close];
    orig_read = sys_call_table[__NR_read];
    orig_write = sys_call_table[__NR_write];
    sys_call_table[__NR_open] = hook_open;
    sys_call_table[__NR_close] = hook_close;
    sys_call_table[__NR_read] = hook_read;
    sys_call_table[__NR_write] = hook_write;
    changed_syscall_ptr = 1;
#else

#endif
    return -1;
}

//static void __exit hook_exit(void){
void cleanup_module() {
    printk(KERN_INFO "hook_exit\n");
    if (changed_syscall_ptr) {
        sys_call_table[__NR_open] = orig_open;
        sys_call_table[__NR_close] = orig_close;
        sys_call_table[__NR_read] = orig_read;
        sys_call_table[__NR_write] = orig_write;
    }
}

/** table search */
unsigned long **find_sys_call_table(void)
{
    unsigned long **sctable;
    unsigned long ptr;

    sctable = NULL;
    printk(KERN_INFO "__NR_open= %ld\n", __NR_open);
    printk(KERN_INFO "__NR_close = %ld\n", __NR_close);
    printk(KERN_INFO "__NR_read= %ld\n", __NR_read);
    printk(KERN_INFO "__NR_write = %ld\n", __NR_write);
    printk(KERN_INFO "kzalloc = %lX\n", (unsigned long)&kzalloc);
    for (ptr = (unsigned long)&strstr;
            ptr < (unsigned long)&kzalloc;
            //ptr += sizeof(void *))
            ptr += 1)
    {
        unsigned long *p;
        p = (unsigned long *)ptr;
        if (p[__NR_close] == (unsigned long) sys_close)
        {  
            sctable = (unsigned long **)p;
            printk(KERN_INFO "Found Table: %ld\n", sctable);
            return &sctable[0];
        }
    }
    return NULL;
}

/** register */

//module_init(hook_init);
//module_exit(hook_exit);

