#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

int main(int argc, char *argv[]) {

    const char *filename = argv[1];
    const char *str = argv[2];

    // open syslog
    openlog(filename, LOG_PID, LOG_USER);

    // Check if both arguments (file name and string) are provided
    if (argc != 3) {
        char error[128];
        sprintf(error, "Usage: %s <filename> <string>\n", argv[0]);
        syslog(LOG_ERR, "%s", error);
        closelog();
        return 1; // Exit with error code 1
    }

    // Open the file for writing (create if it doesn't exist)
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        syslog(LOG_ERR,"%s", strerror(errno));
        closelog();
        return 1; // Exit with error code 1 if file can't be opened
    }

    //Write the string to the file
    fprintf(file, "%s", str);
    syslog(LOG_INFO, "%s", str);

    // Close the file
    fclose(file);
    closelog();

    return 0; // Successful execution
}
