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
#include <time.h>
#include <string.h>
#include "util.h"

#define DEBUG 0

#if DEBUG > 0
#include "syscall_names.h"
#endif

typedef enum syscall_kind {
    syscall_kind_entry,
    syscall_kind_exit
} syscall_kind_t;

struct record {
    int syscall;
    syscall_kind_t kind;
    pid_t pid;
    struct timespec timestamp;
    union {
        /* read */
        struct {
            int fd;
            size_t size;
        } r;
        /* write */
        struct {
            int fd;
            size_t size;
        } w;
        /* open */
        struct {
            int fd;
            char* path;
        } o;
        /* close */
        struct {
            int fd;
        } c;
    } u;
};

FILE* make_logfile();
void write_metadata(FILE* fp, int argc, char** argv, int target_pid);
void output_log(FILE* fp, struct record r);
void getpath(char* path, int pid, unsigned long pathaddr);

void config_record_open(struct record* rec, int syscall, syscall_kind_t kind, pid_t pid, int fd, const char* path) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    rec->syscall = syscall;
    rec->kind = kind;
    rec->pid = pid;
    memcpy(&rec->timestamp, &ts, sizeof(struct timespec));
    rec->u.o.fd = fd;
    rec->u.o.path = safe_strdup(path);
    return;
}

void config_record_close(struct record* rec, int syscall, syscall_kind_t kind, pid_t pid, int fd) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    rec->syscall = syscall;
    rec->kind = kind;
    rec->pid = pid;
    memcpy(&rec->timestamp, &ts, sizeof(struct timespec));
    rec->u.c.fd = fd;
    return;
}

void config_record_read(struct record* rec, int syscall, syscall_kind_t kind, pid_t pid, int fd, size_t size) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    rec->syscall = syscall;
    rec->kind = kind;
    rec->pid = pid;
    memcpy(&rec->timestamp, &ts, sizeof(struct timespec));
    rec->u.r.fd = fd;
    rec->u.r.size= size;
    return;
}

void config_record_write(struct record* rec, int syscall, syscall_kind_t kind, pid_t pid, int fd, size_t size) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    rec->syscall = syscall;
    rec->kind = kind;
    rec->pid = pid;
    memcpy(&rec->timestamp, &ts, sizeof(struct timespec));
    rec->u.w.fd = fd;
    rec->u.w.size = size;
    return;
}


int main(int argc, char** argv) {
    long ret;
    int pid, newpid;
    int status, waitpid_options = 0;
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
    /* Prepare a log file */
    FILE* logfp = make_logfile("log/");
    write_metadata(logfp, argc, argv, pid);
    // pid's purpose changed
    int syscall;
    struct user_regs_struct u_in;
    char path[PATH_MAX];
    int syscall_fd;  // I/O argument 'fd'
    size_t syscall_size;  // read/write argument 'size'
    /* prepare logging */
    int nr_records = 100;
    int cur_record = 0;
    struct record* rs;
    rs = (struct record*)safe_malloc(sizeof(struct record) * nr_records);
    /* main loop */
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
        }
        /* Check the GP register and get the system call number*/
        ptrace(PTRACE_GETREGS, pid, 0, &u_in);
        syscall = u_in.orig_rax;
        if(u_in.rax == -ENOSYS) {
            /* Entry hook */
            if(syscall == __NR_open) {
                getpath(path, pid, u_in.rdi);
                config_record_open(rs + cur_record, syscall, syscall_kind_entry,
                        pid, 0, path);
                cur_record++;
            } else if (syscall == __NR_close) {
                syscall_fd = u_in.rdi;
                config_record_close(rs + cur_record, syscall, syscall_kind_entry,
                        pid, syscall_fd);
                cur_record++;
            } else if (syscall == __NR_read) {
                syscall_fd = u_in.rdi;
                // buf is rsi
                syscall_size = u_in.rdx;
                config_record_read(rs + cur_record, syscall, syscall_kind_entry,
                        pid, syscall_fd, syscall_size);
                cur_record++;
            } else if (syscall == __NR_write) {
                syscall_fd = u_in.rdi;
                // buf is rsi
                syscall_size = u_in.rdx;
                config_record_write(rs + cur_record, syscall, syscall_kind_entry,
                        pid, syscall_fd, syscall_size);
                cur_record++;
            } else {
            }
        } else {
            /* Exit hook */
            long retvalue = u_in.rax;
            if(syscall == __NR_fork) {
                newpid = retvalue;
                ptrace(PTRACE_ATTACH, newpid, NULL, NULL);
                ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            } else if(syscall == __NR_clone) {
                newpid = retvalue;
                ptrace(PTRACE_ATTACH, newpid, NULL, NULL);
                ptrace(PTRACE_SYSCALL, newpid, NULL, NULL);
            } else if(syscall == __NR_vfork) {
                newpid = retvalue;
                ptrace(PTRACE_ATTACH, newpid, NULL, NULL);
                ptrace(PTRACE_SYSCALL, newpid, NULL, NULL);
            } else if(syscall == __NR_open) {
                syscall_fd = retvalue;
                config_record_open(rs + cur_record, syscall, syscall_kind_exit,
                        pid, syscall_fd, NULL);
                cur_record++;
            } else if(syscall == __NR_close) {
                syscall_fd = u_in.rdi;
                config_record_close(rs + cur_record, syscall, syscall_kind_exit,
                        pid, syscall_fd);
                cur_record++;
            } else if(syscall == __NR_read) {
                syscall_fd = u_in.rdi;
                syscall_size = u_in.rsi;
                config_record_read(rs + cur_record, syscall, syscall_kind_exit,
                        pid, syscall_fd, 0);
                cur_record++;
            } else if(syscall == __NR_write) {
                syscall_fd = u_in.rdi;
                syscall_size = u_in.rsi;
                config_record_write(rs + cur_record, syscall, syscall_kind_exit,
                        pid, syscall_fd, 0);
                cur_record++;
            }
        }
        // release
        ret = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        // output log if necessary
        if (cur_record + 1 == nr_records) {
            int i;
            // write logs!
            for(i = 0; i < cur_record; i++) {
                //struct record r = rs[i];
                output_log(logfp, rs[i]);
            }
            cur_record = 0;
        }
    }
#if DEBUG > 1
    fprintf(logfp, "cur_record=%d\n", cur_record);
#endif
    if (cur_record != 0) {
        int i;
        // write logs!
        for(i = 0; i < cur_record; i++) {
            //struct record r = rs[i];
            output_log(logfp, rs[i]);
        }
    }
    free(rs);
    return 0;
}

void output_log(FILE* fp, struct record r) {
    fprintf(fp, "%d %d %d %ld.%09ld ", r.syscall, r.kind, r.pid, r.timestamp.tv_sec,
            r.timestamp.tv_nsec);
    if (r.syscall == __NR_read) {
        fprintf(fp, "%d %lu\n", r.u.r.fd, r.u.r.size);
    } else if (r.syscall == __NR_close) {
        fprintf(fp, "%d\n", r.u.c.fd);
    } else if (r.syscall == __NR_open) {
        fprintf(fp, "%d %s\n", r.u.o.fd, r.u.o.path);
        free(r.u.o.path);
    } else if (r.syscall == __NR_write) {
        fprintf(fp, "%d %lu\n", r.u.w.fd, r.u.w.size);
    }
}

/**
 * Create a log file that has unique file name.
 */
FILE* make_logfile(char* prefix) {
    int i;
    int self_pid = getpid();
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    unsigned long hash = 0;
    // host name hashing
    unsigned long name_hash = 0;
    char hostname[HOST_NAME_MAX + 1];
    gethostname(hostname, HOST_NAME_MAX);
    assert(hostname[HOST_NAME_MAX - 1] == '\0');
    for (i = 0; hostname[i]; i++) {
        name_hash += i * hostname[i];
    }
    // time hashing
    unsigned time_hash = 0;
    time_hash = ts.tv_sec ^ ts.tv_nsec;
    // hashing
    hash = time_hash ^ (name_hash << 32) ^ self_pid;
    // create a file name
    char filename[NAME_MAX];
    sprintf(filename, "%s%ld.%d.log", prefix, hash, self_pid);
    // create a file
    FILE* fp = fopen(filename, "w");
    if(!fp) {
        perror("fopen");
        exit(2);
    }
    return fp;
}

void write_metadata(FILE* fp, int argc, char** argv, int target_pid) {
    int self_pid = getpid();
    int i;
    fprintf(fp, "# cmdline:");
    for (i = 1; i < argc; i++) {
        fprintf(fp, " %s", argv[i]);
    }
    fprintf(fp, "\n");
    fprintf(fp, "# self_pid: %d\n", self_pid);
    fprintf(fp, "# target_pid: %d\n", target_pid);
    return;
}

void getpath(char* path, int pid, unsigned long pathaddr) {
    int i;
    errno = 0;
    for (i = 0; i < PATH_MAX; i++) {
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

/* vim: set ts=4 : */

