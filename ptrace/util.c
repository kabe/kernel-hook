#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

char* safe_strdup(const char* src) {
    char* dst;
    if(src == NULL) {
        return NULL;
    }
    dst = strdup(src);
    if(!dst) {
        perror("dst");
        exit(1);
    }
    return dst;
}

void* safe_malloc(ssize_t size) {
    void* p = malloc(size);
    if(!p) {
        perror("malloc");
        exit(1);
    }
    return p;
}

