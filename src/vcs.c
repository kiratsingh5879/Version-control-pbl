/*
 * Simple VCS (Version Control System) - Phase 2
 * Now with content-addressable storage (Git-like)
 * Compatible with Windows
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <direct.h>
#include <io.h>
#include <time.h>
#include <windows.h>

#define VCS_DIR ".myvcs"
#define OBJECTS_DIR ".myvcs/objects"
#define INDEX_FILE ".myvcs/index"
#define LOG_FILE ".myvcs/log"
#define COMMIT_FILE ".myvcs/commit_id"

// Simple custom hash function (NOT cryptographically secure)
void simple_hash_file(const char *filename, char *output) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        strcpy(output, "0000000000000000000000000000000000000000");
        return;
    }

    unsigned long hash = 5381;
    int c;
    while ((c = fgetc(file)) != EOF) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    fclose(file);

    sprintf(output, "%040lx", hash); // pad to 40 chars with leading zeros
}

void init_repo() {
    if (_mkdir(VCS_DIR) == 0) {
        _mkdir(OBJECTS_DIR);
        FILE *f = fopen(INDEX_FILE, "w"); if (f) fclose(f);
        f = fopen(LOG_FILE, "w"); if (f) fclose(f);
        printf("Repository initialized.\n");
    } else {
        printf("Repository already exists.\n");
    }
}

void add_file(const char *filename) {
    FILE *index = fopen(INDEX_FILE, "a");
    if (!index) return;

    fprintf(index, "%s\n", filename);
    fclose(index);
    printf("Added '%s' to staging.\n", filename);
}

void write_object(const char *filename, const char *hash) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", OBJECTS_DIR, hash);

    if (_access(path, 0) == 0) return; // already stored

    FILE *src = fopen(filename, "rb");
    FILE *dest = fopen(path, "wb");
    if (!src || !dest) return;

    char buffer[1024];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        fwrite(buffer, 1, n, dest);
    }

    fclose(src);
    fclose(dest);
}

void commit(const char *message) {
    char commit_id[64];
    time_t now = time(NULL);
    snprintf(commit_id, sizeof(commit_id), "%ld", now);

    FILE *index = fopen(INDEX_FILE, "r");
    if (!index) return;

    char filename[256];
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) {
        fclose(index);
        return;
    }

    fprintf(log, "commit %s\nmessage: %s\nfiles:\n", commit_id, message);

    while (fgets(filename, sizeof(filename), index)) {
        filename[strcspn(filename, "\n")] = 0;

        char hash[41];
        simple_hash_file(filename, hash);
        write_object(filename, hash);

        fprintf(log, "- %s : %s\n", filename, hash);
    }

    fprintf(log, "\n");
    fclose(index);
    fclose(log);

    index = fopen(INDEX_FILE, "w");
    if (index) fclose(index);

    // Save the commit id
    FILE *commit_file = fopen(COMMIT_FILE, "w");
    if (commit_file) {
        fprintf(commit_file, "%s", commit_id);
        fclose(commit_file);
    }

    printf("Committed as %s\n", commit_id);
}

void show_log() {
    FILE *log = fopen(LOG_FILE, "r");
    if (!log) return;

    char line[256];
    while (fgets(line, sizeof(line), log)) {
        printf("%s", line);
    }
    fclose(log);
}

void show_status() {
    FILE *index = fopen(INDEX_FILE, "r");
    if (!index) return;

    char filename[256];
    char current_hash[41];
    char last_commit_hash[41];
    FILE *commit_file = fopen(COMMIT_FILE, "r");
    if (commit_file) {
        fgets(last_commit_hash, sizeof(last_commit_hash), commit_file);
        fclose(commit_file);
    } else {
        strcpy(last_commit_hash, "0000000000000000000000000000000000000000");
    }

    printf("Changes not yet committed:\n");

    while (fgets(filename, sizeof(filename), index)) {
        filename[strcspn(filename, "\n")] = 0;
        
        // Check current file hash
        simple_hash_file(filename, current_hash);

        // Compare current hash with the hash in the last commit
        if (strcmp(current_hash, last_commit_hash) != 0) {
            printf("- %s (modified)\n", filename);
        }
    }

    fclose(index);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: vcs <command> [args]\n");
        return 1;
    }

    if (strcmp(argv[1], "init") == 0) {
        init_repo();
    } else if (strcmp(argv[1], "add") == 0 && argc == 3) {
        add_file(argv[2]);
    } else if (strcmp(argv[1], "commit") == 0 && argc == 3) {
        commit(argv[2]);
    } else if (strcmp(argv[1], "log") == 0) {
        show_log();
    } else if (strcmp(argv[1], "status") == 0) {
        show_status();
    } else {
        printf("Unknown or invalid command.\n");
    }

    return 0;
}
