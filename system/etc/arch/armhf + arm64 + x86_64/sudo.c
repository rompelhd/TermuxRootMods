#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VERSION "1.0.20"

char *find_su() {
    const char *paths[] = {
        "/debug_ramdisk/su",  // Prioritize Magisk path
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
        "/su/bin/su",
        "/sbin/.magisk/busybox",
        NULL
    };

    for (int i = 0; paths[i]; i++) {
        if (access(paths[i], X_OK) == 0) {
            return strdup(paths[i]);
        }
    }

    return NULL;
}

void show_help(const char *prog) {
    printf("%s - Run commands as root or another user\n", prog);
    printf("Usage:\n");
    printf("  %s [-E] [-u user] command [args...]\n", prog);
    printf("Options:\n");
    printf("  -E            Preserve environment variables\n");
    printf("  -u user       Run as another user (requires root)\n");
    printf("  --version     Show version\n");
    printf("  --help        Show this help\n");
}

int main(int argc, char *argv[]) {
    int preserve_env = 0;
    char *user = NULL;
    int arg_start = 1;

    if (argc < 2) {
        show_help(argv[0]);
        return 1;
    }

    while (arg_start < argc) {
        if (strcmp(argv[arg_start], "-E") == 0) {
            preserve_env = 1;
            arg_start++;
        } else if (strcmp(argv[arg_start], "-u") == 0) {
            if (arg_start + 1 >= argc) {
                fprintf(stderr, "Error: missing username for -u\n");
                return 1;
            }
            user = argv[arg_start + 1];
            arg_start += 2;
        } else if (strcmp(argv[arg_start], "--help") == 0) {
            show_help(argv[0]);
            return 0;
        } else if (strcmp(argv[arg_start], "--version") == 0) {
            printf("sudo by Rompelhd TermuxRootMods %s\n", VERSION);
            return 0;
        } else {
            break;
        }
    }

    if (arg_start >= argc) {
        fprintf(stderr, "Error: no command provided\n");
        return 1;
    }

    char *su_path = find_su();
    if (!su_path) {
        fprintf(stderr, "Error: 'su' binary not found. Are you rooted?\n");
        return 1;
    }

    int total = 0;
    for (int i = arg_start; i < argc; i++) {
        total += strlen(argv[i]) + 1;
    }

    char *cmd = malloc(total + 1);
    if (!cmd) {
        perror("malloc");
        free(su_path);
        return 1;
    }

    cmd[0] = '\0';
    for (int i = arg_start; i < argc; i++) {
        strcat(cmd, argv[i]);
        if (i != argc - 1) strcat(cmd, " ");
    }

    char *args[6];
    int i = 0;
    args[i++] = su_path;

    if (user) {
        args[i++] = user;
    }

    args[i++] = "-c";

    char full_cmd[1024];
    if (preserve_env) {
        snprintf(full_cmd, sizeof(full_cmd), "%s", cmd);
    } else {
        snprintf(full_cmd, sizeof(full_cmd),
                 "env -i PATH=/data/data/com.termux/files/usr/bin:/system/bin:/system/xbin:/usr/bin:/sbin HOME=/root TERM=xterm-256color %s", cmd);
    }

    args[i++] = full_cmd;
    args[i] = NULL;

    char *new_env[] = {
        "PATH=/data/data/com.termux/files/usr/bin:/system/bin:/system/xbin:/usr/bin:/sbin",
        "HOME=/root",
        "TERM=xterm-256color",
        "MAGISK_VER=29",  // Include Magisk version for compatibility
        NULL
    };

    if (preserve_env) {
        execve(su_path, args, environ);
    } else {
        execve(su_path, args, new_env);
    }

    perror("execve failed");

    free(su_path);
    free(cmd);
    return 1;
}
