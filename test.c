#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    // Get and print the effective user and group IDs
    uid_t euid = geteuid();  // Get effective user ID
    gid_t egid = getegid();  // Get effective group ID

    printf("Effective User ID: %d\n", euid);
    printf("Effective Group ID: %d\n", egid);

    // Check if the current user is root (UID 0)
    if (euid == 0) {
        printf("Running as root!\n");
    } else {
        printf("Not running as root.\n");
    }

    return 0;
}

