#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include "syscall_names.h"

void getpath(char* path, int pid, unsigned long pathaddr);

int main(int argc, char** argv) {
    long ret;
    int pid, newpid;
    int status, waitpid_options = 0;
    void* data;
    int syscall;
    struct user_regs_struct u_in;
    char path[PATH_MAX];
    pid = fork();
    if(pid) { // parent
        wait(&status);
        // first TRAP command
        ret = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        if(ret) {
            perror("ptrace");
            exit(1);
        }
    } else { // child
        ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if(ret) {
            perror("ptrace");
            exit(1);
        }
        // exec: after success, it will seem to be stopped by SIGTRAP
        argv[argc] = 0;
        execvp(argv[1], argv + 1);
    }
    // pid's purpose changed
    while(1) {
        pid = waitpid(-1, &status, waitpid_options);
        if (pid < 0) {
            if (errno == ECHILD) {
                break;
            } else {
                perror("wait");
                exit(2);
            }
        } else if(WIFEXITED(status)) {
            continue;
        } else if (WIFSIGNALED(status)) {
            continue;
        }        /* Check the GP register and get the system call number*/
        ptrace(PTRACE_GETREGS, pid, 0, &u_in);
        syscall = u_in.orig_rax;
        if(u_in.rax == -ENOSYS) {
            /* Entry hook */
            if(syscall == __NR_open) {
                getpath(path, pid, u_in.rdi);
                printf("(pid=%d) %s\n", pid, syscall_names[syscall]); /* System call name */
                printf("%s ", syscall_names[syscall]); /* System call name */
                printf("%08lx(%s) ", u_in.rdi, (char*)path); /* Address of the path */
                printf("%08lx ", u_in.rsi); /* Flag */
                printf("%08lx\n", u_in.rdx); /* Mode */
            } else {
                printf("(pid=%d) Syscall: %s\n", pid, syscall_names[syscall]);
            }
        } else {
            /* Exit hook */
            long retvalue = u_in.rax;
            if(syscall == __NR_fork) {
                newpid = retvalue;
                printf("(pid=%d) fork hooked: newpid = %d\n", pid, newpid);
                ptrace(PTRACE_ATTACH, newpid, NULL, NULL);
                ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            } else if(syscall == __NR_clone) {
                newpid = retvalue;
                printf("(pid=%d) clone hooked: newpid = %d\n", pid, newpid);
                ptrace(PTRACE_ATTACH, newpid, NULL, NULL);
                ptrace(PTRACE_SYSCALL, newpid, NULL, NULL);
            } else if(syscall == __NR_vfork) {
                newpid = retvalue;
                printf("(pid=%d) vfork hooked: newpid = %d\n", pid, newpid);
                ptrace(PTRACE_ATTACH, newpid, NULL, NULL);
                ptrace(PTRACE_SYSCALL, newpid, NULL, NULL);
            } else {
                newpid = u_in.rax;
                printf("(pid=%d) some called: v=%d\n", pid, newpid);
            }
        }
        // release
        ret = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        // output log if necessary
    }
    return 0;
}

void getpath(char* path, int pid, unsigned long pathaddr) {
    int i;
    errno = 0;
    jjfor (i = 0; i < PATH_MAX; i++) {
        if ((i & 0x7) == 0) {
            unsigned long chunk = ptrace(PTRACE_PEEKDATA, pid, (char *)(pathaddr + i), 0);
            if (errno != 0)
                break;
            *((long *) (&path[i])) = chunk;
        }
        if (path[i] == 0) {
            break;
        }
    }
}
/*
   struct user_regs_struct
   {
   unsigned long r15;
   unsigned long r14;
   unsigned long r13;
   unsigned long r12;
   unsigned long rbp;
   unsigned long rbx;
   unsigned long r11;
   unsigned long r10;
   unsigned long r9;
   unsigned long r8;
   unsigned long rax;
   unsigned long rcx;
   unsigned long rdx;
   unsigned long rsi;
   unsigned long rdi;
   unsigned long orig_rax;
   unsigned long rip;
   unsigned long cs;
   unsigned long eflags;
   unsigned long rsp;
   unsigned long ss;
   unsigned long fs_base;
   unsigned long gs_base;
   unsigned long ds;
   unsigned long es;
   unsigned long fs;
   unsigned long gs;
   };
   */

