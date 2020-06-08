#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct s {
    char* top;
    char* max;
    char buf[];
};

struct s* s_init(void *p, size_t size) {
    struct s* m = p;
    m->max = (char*)(p) + size;
    m->top = m->buf;
    return m;
}

void* s_alloc(struct s* m, size_t size) {
    void* p = 0;
    size_t a = m->max - m->top;
    if (a > size) {
        p = m->top;
        m->top += size;
    }
    return p;
}

void s_free(struct s* m, void *p) {
    m->top = p;
}

void* _calloc(struct s* m, unsigned long n, unsigned long size) {
    void* p = s_alloc(m, n * size);
    if (p) {
        memset(p, 0, n * size);
    }
    return p;
}

int read_flag(struct s* m) {
    char *test = s_alloc(m, 32);
    FILE* flag_file = fopen("flag.txt", "r");
    if (!flag_file) {
        return 0;
    }
    char* flag = s_alloc(m, 32);
    if (!flag) {
        fclose(flag_file);
        return 0;
    }
    int result = 0;
    if (fgets(flag, 32, flag_file)) {
        result = 1;
    }
    fclose(flag_file);
    s_free(m, test);
    return result;
}

int main() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
    printf("welcome to my PGM creator!\ninput: ");
    static char buf[1024];
    struct s* m = s_init(buf, sizeof(buf));
    if (!read_flag(m)) {
        fputs("Failed to read flag. Contact an admin.", stderr);
        exit(EXIT_FAILURE);
    }
    char line[256];
    char *p = line;
    if (!fgets(line, sizeof(line), stdin)) {
        fputs("failed\n", stderr);
        exit(EXIT_FAILURE);
    }
    unsigned long width = strtoul(p, &p, 10);
    unsigned long height = strtoul(p, &p, 10);
    unsigned char* pixels = _calloc(m, width, height);
    if (!pixels) {
        fputs("failed\n", stderr);
        exit(EXIT_FAILURE);
    }
    while (fgets(line, sizeof(line), stdin)) {
        unsigned long x, y;
        char *p = line;
        if (p[0] == '\n') {
            break;
        }
        x = strtoul(p, &p, 10);
        y = strtoul(p, &p, 10);
        if (x < width && y < height) {
            pixels[y * width + x] = strtoul(p, &p, 16);;
        }
    }
    printf("P3\n%ld %ld 255\n", width, height);
    for (unsigned long y = 0; y < height; y++) {
        for (unsigned long x = 0; x < width; x++) {
            printf("%d ", pixels[y * width + x]);
        }
        putchar('\n');
    }
}
