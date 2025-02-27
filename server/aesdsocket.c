#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h> //open
#include <sys/stat.h> // umask


#define MAX_MSG_SIZE 1024*1024
const char* AESDSOCKETDATA = "/var/tmp/aesdsocketdata";
const char* PORT = "9000";

int sfd, cfd;
FILE *dataFile;

volatile sig_atomic_t close_syslog_flag = 0;

void signal_handler(int signum) {

    int errno_saved = errno;

    syslog(LOG_DEBUG, "Caught signal: %d", signum);

    // Close fds
    syslog(LOG_DEBUG, "Closing client socket fd: %d", cfd);
    close(cfd);
    syslog(LOG_DEBUG, "Closing server socket fd: %d", sfd);
    close(sfd);
    syslog(LOG_DEBUG, "Closing dataFile");
    fclose(dataFile);

    if (remove(AESDSOCKETDATA) == 0) {
        syslog(LOG_DEBUG, "%s deleted successfully", AESDSOCKETDATA);
    } else {
        syslog(LOG_ERR, "failed to delete file %s", AESDSOCKETDATA);
    }

    close_syslog_flag = 1;

    errno = errno_saved;

    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {

    // open syslog
    openlog("aesdsocket", LOG_PID, LOG_USER);

    int status;
    struct addrinfo hints;
    struct addrinfo *rp, *result;  // will point to the results
    struct sockaddr_storage their_addr;
    socklen_t addr_size;
    char ip_str[INET_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints); // make sure the struct is empty
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_INET;     // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    hints.ai_protocol = 0;         // any
    hints.ai_flags = AI_PASSIVE;     // fill in my IP for me

    if ((status = getaddrinfo(NULL, PORT, &hints, &result)) != 0) {
        syslog(LOG_ERR, "getaddrinfo error: %s", gai_strerror(status));
        closelog();
        exit(-1);
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {

        // Create a socket
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        
        // try next
        if (sfd < 0) {
            continue;
        }
        
        syslog(LOG_DEBUG, "Socket created successfully with file descriptor: %d", sfd);

        // Set the SO_REUSEADDR option
        int opt = 1;
        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            syslog(LOG_ERR, "Error: setsockopt SOL_SOCKET (%d) failed", opt);
            close(sfd);
            closelog();
            exit(-1);
        }

        if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            inet_ntop(AF_INET, &(((struct sockaddr_in *)rp->ai_addr)->sin_addr), ip_str, sizeof(ip_str));
            syslog(LOG_DEBUG, "Socket was binded successfully for address: %s", ip_str);
            break;
        }

        close(sfd);
    }

    freeaddrinfo(result);   /* result is no longer needed */

    // Check for errors
    if (rp == NULL) {
        syslog(LOG_ERR, "Error %d (%s) creating socket", errno, strerror(errno));
        close(sfd);
        closelog();
        exit(-1);
    }
    
    // create a listener
    if (listen(sfd, 20) == -1) {
        syslog(LOG_ERR, "Error %d (%s) listen on socket %d", errno, strerror(errno), sfd);
        close(sfd);
        closelog();
        exit(-1);
    }

    syslog(LOG_DEBUG, "server: waiting for connections...");

    // Register signals
    struct sigaction sa;
    memset(&sa,0,sizeof(struct sigaction));
    sa.sa_handler=signal_handler;
    if( sigaction(SIGTERM, &sa, NULL) != 0 ) {
        syslog(LOG_ERR, "Error %d (%s) registering for SIGTERM", errno, strerror(errno));
        close(sfd);
        closelog();
        exit(-1);
    }
    if( sigaction(SIGINT, &sa, NULL) ) {
        syslog(LOG_ERR, "Error %d (%s) registering for SIGINT", errno, strerror(errno));
        close(sfd);
        closelog();
        exit(-1);
    }

    // Get program options
    int daemonize = 0; // Flag to indicate daemon mode
    int opt;

    while ((opt = getopt(argc, argv, "d")) != -1) {
        switch (opt) {
            case 'd':
                daemonize = 1;
                break;
            case '?': // Handle unknown options
                fprintf(stderr, "Usage: %s [-d]\n", argv[0]);
                return 1;
            default:
                break;
        }
    }

    /*********** Daemonize ************/  
    if (daemonize) {

        pid_t pid;

        // First fork
        pid = fork();
        if (pid < 0) {
            syslog(LOG_ERR, "first fork failed");
            close(sfd);
            closelog();
            exit(-1);
        }
        if (pid > 0) {
            syslog(LOG_DEBUG, "creating a daemon, first fork success, parent exits");
            exit(EXIT_SUCCESS); // Parent exits
        }

        // Create new session
        if (setsid() < 0) {
            syslog(LOG_ERR, "setsid failed");
            close(sfd);
            closelog();
            exit(-1);
        }

        // Second fork
        pid = fork();
        if (pid < 0) {
            syslog(LOG_ERR, "second fork failed");
            close(sfd);
            closelog();
            exit(-1);
        }
        if (pid > 0) {
            syslog(LOG_DEBUG, "creating a daemon, second fork success, first child exits");
            exit(EXIT_SUCCESS); // First child exits
        }

        // Change working directory
        if (chdir("/") < 0) {
            syslog(LOG_ERR, "chdir failed");
            close(sfd);
            closelog();
            exit(-1);
        }

        // Redirect standard file descriptors
        int fd;
        fd = open("/dev/null", O_RDWR);
        if (fd != -1) {
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > 2) {
                close(fd);
            }
        }

        // Clear file mode creation mask
        umask(0);

        syslog(LOG_DEBUG, "Daemon created successfully!");
    }

    /*********** the rest logic here... ************/  
    while (1) {
        addr_size = sizeof their_addr;
        cfd = -1;
        char rcvmsg[MAX_MSG_SIZE];


        // Blocking accept
        if((cfd = accept(sfd, (struct sockaddr *)&their_addr, &addr_size)) < 0) {         
            syslog(LOG_ERR, "Error: recv on socket %d failed", cfd);
            close(sfd);
            closelog();
            exit(-1);
        }

        // Get client address
        inet_ntop(AF_INET, &(((struct sockaddr_in *)&their_addr)->sin_addr), ip_str, sizeof(ip_str));
        syslog(LOG_DEBUG, "New client connection from address: %s", ip_str);

        // Blocking recv: This will wait until data is received
        int len = recv(cfd, rcvmsg, MAX_MSG_SIZE, 0);

        if (len < 0) {
            syslog(LOG_ERR, "Error: recv on socket %d failed", cfd);
            close(cfd);
            close(sfd);
            closelog();
            exit(-1);
        } else if (len == 0) {
            syslog(LOG_DEBUG, "Client on socket %d disconnected", cfd);
        } else {
            for (int i=0; i<len; i++) {
                if (rcvmsg[i] == '\n') {
                    rcvmsg[++i] = '\0';
                    break;
                }
            }
            syslog(LOG_DEBUG, "Data received from client on socket %d: %s", cfd, rcvmsg);
            dataFile = fopen(AESDSOCKETDATA, "a+");
            if (dataFile == NULL) {
                syslog(LOG_ERR,"%s", strerror(errno));
                close(cfd);
                close(sfd);
                closelog();
                exit(-1);
            }
            fprintf(dataFile, "%s", rcvmsg);
            rewind(dataFile);
            while (fgets(rcvmsg, sizeof(rcvmsg), dataFile) != NULL) {
                size_t len = strlen(rcvmsg);
                send(cfd, rcvmsg, len, 0); // Send the received data
            }
        
        }
        if (close_syslog_flag) {
            closelog();
            close_syslog_flag = 0; // Reset the flag
            break; // Or perform other cleanup
        }
    }
    
    // Close files
    // syslog(LOG_DEBUG, "Closing client socket fd: %d", cfd);
    // close(cfd);
    // syslog(LOG_DEBUG, "Closing server socket fd: %d", sfd);
    // close(sfd);
    // syslog(LOG_DEBUG, "Closing syslog");
    // closelog();
    // syslog(LOG_DEBUG, "Closing dataFile");
    // fclose(dataFile);

    return 0;
}