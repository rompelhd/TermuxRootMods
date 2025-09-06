#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#define LOG_FILE "/sdcard/logs.txt"
#define MAX_PATH 1024
#define MAX_COMMAND 1024

void get_timestamp(char *buffer, size_t size) {
    char command[MAX_COMMAND];
    snprintf(command, sizeof(command), "date +'%%d/%%m/%%y %%H:%%M:%%S'");
    FILE *fp = popen(command, "r");
    if (fp) {
        fgets(buffer, size, fp);
        buffer[strcspn(buffer, "\n")] = 0;
        pclose(fp);
    } else {
        snprintf(buffer, size, "Unknown time");
    }
}

void get_dir_size(const char *path, char *size_str, size_t size) {
    struct stat st;
    long long total_size = 0;
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(path))) {
        snprintf(size_str, size, "0");
        return;
    }

    while ((entry = readdir(dir))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char full_path[MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        if (stat(full_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                char sub_size[32];
                get_dir_size(full_path, sub_size, sizeof(sub_size));
                total_size += atoll(sub_size);
            } else {
                total_size += st.st_size;
            }
        }
    }
    closedir(dir);

    if (total_size >= 1024 * 1024)
        snprintf(size_str, size, "%.1fM", total_size / (1024.0 * 1024));
    else if (total_size >= 1024)
        snprintf(size_str, size, "%.1fK", total_size / 1024.0);
    else
        snprintf(size_str, size, "%lldB", total_size);
}

void delete_dir_contents(const char *path, FILE *log_fp) {
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(path)))
        return;

    while ((entry = readdir(dir))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char full_path[MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                delete_dir_contents(full_path, log_fp);
                rmdir(full_path);
            } else {
                unlink(full_path);
            }
        }
    }
    closedir(dir);
}

void clean_cache_app(const char *app_dir, const char *app_name) {
    char cache_path[MAX_PATH], code_cache_path[MAX_PATH];
    char cache_size[32] = "0", code_cache_size[32] = "0";
    char timestamp[32];
    FILE *log_fp = fopen(LOG_FILE, "a");

    snprintf(cache_path, sizeof(cache_path), "%s/cache", app_dir);
    snprintf(code_cache_path, sizeof(code_cache_path), "%s/code_cache", app_dir);

    struct stat st;
    if (stat(cache_path, &st) == 0 && S_ISDIR(st.st_mode))
        get_dir_size(cache_path, cache_size, sizeof(cache_size));
    if (stat(code_cache_path, &st) == 0 && S_ISDIR(st.st_mode))
        get_dir_size(code_cache_path, code_cache_size, sizeof(code_cache_size));

    if (strcmp(cache_size, "0") != 0 || strcmp(code_cache_size, "0") != 0) {
        printf("Deleting cache for %s (Cache: %s, Code Cache: %s)...\n", app_name, cache_size, code_cache_size);
        if (log_fp) {
            get_timestamp(timestamp, sizeof(timestamp));
            fprintf(log_fp, "[%s] Deleting cache for %s (Cache: %s, Code Cache: %s)\n", timestamp, app_name, cache_size, code_cache_size);
        }

        delete_dir_contents(cache_path, log_fp);
        delete_dir_contents(code_cache_path, log_fp);
    }

    if (log_fp)
        fclose(log_fp);
}

void cleaner() {
    system("clear");
    printf("Cleaner In TermuxRootMods By Rompelhd\n");
    printf("Cleaning apps cache...\n");

    FILE *log_fp = fopen(LOG_FILE, "a");
    if (log_fp) {
        char timestamp[32];
        get_timestamp(timestamp, sizeof(timestamp));
        fprintf(log_fp, "[%s] Cleaning apps cache... (TermuxRootMods)\n", timestamp);
        fclose(log_fp);
    }

    // Clean /data/data/*/cache and /data/data/*/code_cache
    printf("Deleting files from /data/data/*/cache and /data/data/*/code_cache...\n");
    DIR *dir = opendir("/data/data");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir))) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            char app_dir[MAX_PATH];
            snprintf(app_dir, sizeof(app_dir), "/data/data/%s", entry->d_name);
            clean_cache_app(app_dir, entry->d_name);
        }
        closedir(dir);
    }

    // Clean /data/user_de/*/*/cache and /data/user_de/*/*/code_cache
    printf("Deleting files from /data/user_de/*/*/cache and /data/user_de/*/*/code_cache...\n");
    dir = opendir("/data/user_de");
    if (dir) {
        struct dirent *user_entry;
        while ((user_entry = readdir(dir))) {
            if (strcmp(user_entry->d_name, ".") == 0 || strcmp(user_entry->d_name, "..") == 0)
                continue;

            char user_dir[MAX_PATH];
            snprintf(user_dir, sizeof(user_dir), "/data/user_de/%s", user_entry->d_name);
            DIR *app_dir = opendir(user_dir);
            if (app_dir) {
                struct dirent *app_entry;
                while ((app_entry = readdir(app_dir))) {
                    if (strcmp(app_entry->d_name, ".") == 0 || strcmp(app_entry->d_name, "..") == 0)
                        continue;

                    char full_app_dir[MAX_PATH];
                    snprintf(full_app_dir, sizeof(full_app_dir), "%s/%s", user_dir, app_entry->d_name);
                    clean_cache_app(full_app_dir, app_entry->d_name);
                }
                closedir(app_dir);
            }
        }
        closedir(dir);
    }

    // Clean /sdcard/Android/data/*/cache
    printf("Deleting files from /sdcard/Android/data/*/cache...\n");
    dir = opendir("/sdcard/Android/data");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir))) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            char app_dir[MAX_PATH];
            snprintf(app_dir, sizeof(app_dir), "/sdcard/Android/data/%s", entry->d_name);
            char cache_path[MAX_PATH];
            snprintf(cache_path, sizeof(cache_path), "%s/cache", app_dir);

            char cache_size[32] = "0";
            struct stat st;
            if (stat(cache_path, &st) == 0 && S_ISDIR(st.st_mode))
                get_dir_size(cache_path, cache_size, sizeof(cache_size));

            if (strcmp(cache_size, "0") != 0) {
                printf("Deleting cache for %s (Cache: %s)...\n", entry->d_name, cache_size);
                log_fp = fopen(LOG_FILE, "a");
                if (log_fp) {
                    char timestamp[32];
                    get_timestamp(timestamp, sizeof(timestamp));
                    fprintf(log_fp, "[%s] Deleting cache for %s (Cache: %s)\n", timestamp, entry->d_name, cache_size);
                    fclose(log_fp);
                }
                delete_dir_contents(cache_path, log_fp);
            }
        }
        closedir(dir);
    }

    log_fp = fopen(LOG_FILE, "a");
    if (log_fp) {
        char timestamp[32];
        get_timestamp(timestamp, sizeof(timestamp));
        fprintf(log_fp, "[%s] Done! The apps cache has been cleaned!\n\n", timestamp);
        fclose(log_fp);
    }
    printf("Done! The apps cache has been cleaned!\n");
}

int main() {
    if (geteuid() != 0) {
        printf("Run this command with root privileges!\n");
        return 1;
    }

    system("clear");
    printf("Running script...\n");
    cleaner();
    return 0;
}
