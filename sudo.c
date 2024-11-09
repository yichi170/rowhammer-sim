#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include <sys/types.h>
#include <sys/wait.h>

#define PASSWORD_MAX_LENGTH 128

int check_password(const char *username, const char *entered_password) {
    struct passwd *pwd = getpwnam(username);
    if (pwd == NULL) {
        fprintf(stderr, "User not found\n");
        return 0;
    }

    struct spwd *shadow = getspnam(username); // readable only by root
    if (shadow == NULL) {
        fprintf(stderr, "No shadow password entry for user or no permission\n");
        return 0;
    }

    // Use crypt to check the hashed password
    char *correct_hash = shadow->sp_pwdp;
    char *entered_hash = crypt(entered_password, correct_hash);

    return (entered_hash != NULL && strcmp(entered_hash, correct_hash) == 0);
}

void run_command(char *command) {
    if (fork() == 0) {
        if (setuid(geteuid()) == -1) {
            perror("Failed to elevate to root");
            exit(EXIT_FAILURE);
        }

        char *args[] = {"/bin/sh", "-c", command, NULL};
        execvp(args[0], args);
        perror("execvp failed");
        exit(EXIT_FAILURE);
    } else {
        wait(NULL);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *username = getlogin();
    if (username == NULL) {
        perror("getlogin failed");
        return EXIT_FAILURE;
    }

    char entered_password[PASSWORD_MAX_LENGTH];
    printf("Enter password for %s: ", username);
    if (fgets(entered_password, sizeof(entered_password), stdin) == NULL) {
        perror("Error reading password");
        return EXIT_FAILURE;
    }
    entered_password[strcspn(entered_password, "\n")] = 0;

    if (!check_password(username, entered_password)) {
        fprintf(stderr, "Authentication failed\n");
        return EXIT_FAILURE;
    }

    printf("Password accepted. Executing command: %s\n", argv[1]);
    run_command(argv[1]);

    return EXIT_SUCCESS;
}
