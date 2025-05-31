#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>

#define VERSION "1.0.11"

char *find_su() {
    const char *paths[] = {
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
    printf("  %s [-E] [-u user|#uid] [-g group] [-s] [-i] command [args...]\n", prog);
    printf("Options:\n");
    printf("  -E            Preserve environment variables\n");
    printf("  -u user|#uid  Run as another user or UID (requires root)\n");
    printf("  -g group      Run as specified group (requires root)\n");
    printf("  -s            Run command in a shell (/bin/sh)\n");
    printf("  -i            Run an interactive login shell\n");
    printf("  --version     Show version\n");
    printf("  --help        Show this help\n");
}

int is_numeric(const char *str) {
    if (!str || *str == '\0') return 0;
    for (int i = 0; str[i]; i++) {
        if (!isdigit(str[i])) return 0;
    }
    return 1;
}

int validate_user(const char *user) {
    if (!user) return 1;
    if (is_numeric(user)) {
        uid_t uid = atoi(user);
        struct passwd *pw = getpwuid(uid);
        if (!pw) {
            fprintf(stderr, "Error: UID '%s' does not exist\n", user);
            return 0;
        }
    } else {
        struct passwd *pw = getpwnam(user);
        if (!pw) {
            fprintf(stderr, "Error: user '%s' does not exist\n", user);
            return 0;
        }
    }
    return 1;
}

int validate_group(const char *group) {
    if (!group) return 1;
    struct group *gr = getgrnam(group);
    if (!gr) {
        fprintf(stderr, "Error: group '%s' does not exist\n", group);
        return 0;
    }
    return 1;
}

int main(int argc, char *argv[]) {
    int preserve_env = 0;
    char *user = NULL;
    char *group = NULL;
    int use_shell = 0;
    int login_shell = 0;
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
                fprintf(stderr, "Error: missing username or UID for -u\n");
                return 1;
            }
            user = argv[arg_start + 1];
            arg_start += 2;
        } else if (strcmp(argv[arg_start], "-g") == 0) {
            if (arg_start + 1 >= argc) {
                fprintf(stderr, "Error: missing group name for -g\n");
                return 1;
            }
            group = argv[arg_start + 1];
            arg_start += 2;
        } else if (strcmp(argv[arg_start], "-s") == 0) {
            use_shell = 1;
            arg_start++;
        } else if (strcmp(argv[arg_start], "-i") == 0) {
            login_shell = 1;
            arg_start++;
        } else if (strcmp(argv[arg_start], "--help") == 0) {
            show_help(argv[0]);
            return 0;
        } else if (strcmp(argv[arg_start], "--version") == 0) {
            printf("sudo by rompelhd TermuxRootMods %s\n", VERSION);
            return 0;
        } else {
            break;
        }
    }

    if (arg_start >= argc && !login_shell) {
        fprintf(stderr, "Error: no command provided\n");
        return 1;
    }

    if (!validate_user(user) || !validate_group(group)) {
        return 1;
    }

    char *su_path = find_su();
    if (!su_path) {
        fprintf(stderr, "Error: 'su' binary not found. Are you rooted?\n");
        return 1;
    }

    char *cmd = NULL;
    int total = 0;
    if (!login_shell) {
        for (int i = arg_start; i < argc; i++) {
            total += strlen(argv[i]) + 1;
        }
        cmd = malloc(total + 1);
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
    }

    char *args[8];
    int i = 0;
    args[i++] = su_path;

    if (user) {
        args[i++] = user;
    }

    if (group) {
        args[i++] = "-g";
        args[i++] = group;
    }

    if (use_shell || login_shell) {
        args[i++] = "-s";
    }

    args[i++] = "-c";

    char full_cmd[1024];
    if (login_shell) {
        if (preserve_env) {
            snprintf(full_cmd, sizeof(full_cmd), "/bin/sh -l");
        } else {
            snprintf(full_cmd, sizeof(full_cmd),
                     "env -i PATH=/system/bin:/system/xbin:/usr/bin HOME=/root TERM=xterm-256color /bin/sh -l");
        }
    } else if (use_shell) {
        if (preserve_env) {
            snprintf(full_cmd, sizeof(full_cmd), "/bin/sh -c '%s'", cmd);
        } else {
            snprintf(full_cmd, sizeof(full_cmd),
                     "env -i PATH=/system/bin:/system/xbin:/usr/bin HOME=/root TERM=xterm-256color /bin/sh -c '%s'", cmd);
        }
    } else {
        if (preserve_env) {
            snprintf(full_cmd, sizeof(full_cmd), "%s", cmd);
        } else {
            snprintf(full_cmd, sizeof(full_cmd),
                     "env -i PATH=/system/bin:/system/xbin:/usr/bin HOME=/root TERM=xterm-256color %s", cmd);
        }
    }

    args[i++] = full_cmd;
    args[i] = NULL;

    char *new_env[] = {
        "PATH=/system/bin:/system/xbin:/usr/bin",
        "HOME=/root",
        "TERM=xterm-256color",
        NULL
    };

    if (preserve_env) {
        execve(su_path, args, environ);
    } else {
        execve(su_path, args, new_env);
    }

    perror("execve failed");
    if (cmd) free(cmd);
    free(su_path);
    return 1;
}
