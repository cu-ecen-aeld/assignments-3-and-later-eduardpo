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
#include <queue.h>
#include <pthread.h>


#define MAX_MSG_SIZE 1024*1024
const char* AESDSOCKETDATA = "/var/tmp/aesdsocketdata";
const char* PORT = "9000";

int sfd, cfd;
FILE *dataFile;
pthread_mutex_t dataMutex;

// SLIST.
typedef struct slist_data_s slist_data_t;
struct slist_data_s {
    pthread_t t_id;
    bool t_complete;
    int sfd;
    int cfd;
    struct sockaddr_storage* their_addr;
    SLIST_ENTRY(slist_data_s) entries;
};

SLIST_HEAD(slisthead, slist_data_s) head;
//SLIST_INIT(&head);

volatile sig_atomic_t close_syslog_flag = 0;

// POSIX timer variables
timer_t timer_id;

// Signal handler for the timer
void timer_handler(int signo) {

    //syslog(LOG_DEBUG, "Caught signal: %d", signo);

    if (signo == SIGALRM) {
        syslog(LOG_DEBUG, "Caught signal: %d", SIGALRM);
        time_t now = time(NULL);
        struct tm *time_info = localtime(&now);
        char time_str[64];

        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S\n", time_info);

        // Protect file writing with a mutex
        if (pthread_mutex_lock(&dataMutex) != 0) {
            syslog(LOG_ERR,"Failed to lock dataMutex");
            // close(t_data->cfd);
            // close(t_data->sfd);
            closelog();
            exit(-1);
        }

        char time_str_buffer[100];
        sprintf(time_str_buffer, "timestamp:%s", time_str);
        syslog(LOG_DEBUG, "Trying to write to file: %s", time_str_buffer);
        int fd = open(AESDSOCKETDATA, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (dataFile >= 0) {
            write(fd, time_str_buffer, strlen(time_str_buffer));
            close(fd);
        } else {
            syslog(LOG_ERR,"Failed to open file!");
        }

        if (pthread_mutex_unlock(&dataMutex) != 0) {
            syslog(LOG_ERR,"Failed to unlock dataMutex");
            // close(t_data->cfd);
            // close(t_data->sfd);
            closelog();
            exit(-1);
        }
        syslog(LOG_DEBUG, "After critical section");
    }
}

// Function to create and start the POSIX timer
void setup_timer() {
    struct sigevent sev;
    struct itimerspec its;
    struct sigaction sa;

    // Set up signal handler
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = timer_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL) == -1) {
        syslog(LOG_ERR, "sigaction failed");
        exit(-1);
    }

    // Configure timer to send SIGALRM
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGALRM;
    sev.sigev_value.sival_ptr = &timer_id;
    if (timer_create(CLOCK_REALTIME, &sev, &timer_id) == -1) {
        syslog(LOG_ERR, "timer_create failed");
        exit(-1);
    }

    // Set timer to fire every 10 seconds
    its.it_value.tv_sec = 10;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 10;
    its.it_interval.tv_nsec = 0;

    if (timer_settime(timer_id, 0, &its, NULL) == -1) {
        syslog(LOG_ERR, "timer_settime failed");
        exit(-1);
    }
}

void signal_handler(int signum) {

    int errno_saved = errno;
    slist_data_t *t_data, *tmp;

    syslog(LOG_DEBUG, "Caught signal: %d", signum);

     // Remove threads data, free up memory
     syslog(LOG_DEBUG, "Cleaning running threads data...");
     SLIST_FOREACH_SAFE(t_data, &head, entries, tmp) {
        syslog(LOG_DEBUG, "Cleaning thread id: %lu, closing client socket fd: %d", t_data->t_id, t_data->cfd);
        close(t_data->cfd);
        SLIST_REMOVE(&head, t_data, slist_data_s, entries);
        free(t_data); // Free the removed node
    }

    // cleaning
    syslog(LOG_DEBUG, "Closing server socket fd: %d", sfd);
    close(sfd);
    // syslog(LOG_DEBUG, "Closing dataFile");
    // if (fclose(dataFile) != 0) {
    //     syslog(LOG_ERR, "failed to close file");
    // } else {
    //     syslog(LOG_DEBUG, "dataFile is closed successf");
    // }
    if (remove(AESDSOCKETDATA) == 0) {
        syslog(LOG_DEBUG, "%s deleted successfully", AESDSOCKETDATA);
    } else {
        syslog(LOG_ERR, "failed to delete file %s", AESDSOCKETDATA);
    }

    close_syslog_flag = 1;

    errno = errno_saved;

    exit(EXIT_SUCCESS);
}

void *processConnectionThread(void *arg) {

    slist_data_t* t_data = (slist_data_t*)arg;
    char ip_str[INET_ADDRSTRLEN];
    char rcvmsg[MAX_MSG_SIZE];

    syslog(LOG_DEBUG, "Connection thread %lu for client %d is running...", t_data->t_id, t_data->cfd);

    // Logic here
    // Get client address
    inet_ntop(AF_INET, &(((struct sockaddr_in *)t_data->their_addr)->sin_addr), ip_str, sizeof(ip_str));
    syslog(LOG_DEBUG, "New client connection from address: %s", ip_str);

    // Blocking recv: This will wait until data is received
    int len = recv(t_data->cfd, rcvmsg, MAX_MSG_SIZE, 0);

    if (len < 0) {
        syslog(LOG_ERR, "Error: recv on socket %d failed, error: %s (%d)", t_data->cfd, strerror(errno), errno);
        close(t_data->cfd);
        close(t_data->sfd);
        closelog();
        exit(-1);
    } else if (len == 0) {
        syslog(LOG_DEBUG, "Client on socket %d disconnected", t_data->cfd);
    } else {

        for (int i=0; i<len; i++) {
            if (rcvmsg[i] == '\n') {
                rcvmsg[++i] = '\0';
                break;
            }
        }
        syslog(LOG_DEBUG, "Data received from client on socket %d: %s", t_data->cfd, rcvmsg);

        // critical section start
        int rc = pthread_mutex_lock(&dataMutex);
        if (rc != 0 ) {
            syslog(LOG_ERR, "pthread_mutex_lock failed with %d", rc);
            close(t_data->cfd);
            close(t_data->sfd);
            closelog();
            fclose(dataFile);
            exit(-1);
        }
        dataFile = fopen(AESDSOCKETDATA, "a+");
        if (dataFile == NULL) {
            syslog(LOG_ERR,"Failed to open file %s, error: %s (%d)", AESDSOCKETDATA, strerror(errno), errno);
            close(t_data->cfd);
            close(t_data->sfd);
            closelog();
            fclose(dataFile);
            exit(-1);
        }
        fprintf(dataFile, "%s", rcvmsg);

        // send the whole contant back
        rewind(dataFile);
        while (fgets(rcvmsg, sizeof(rcvmsg), dataFile) != NULL) {
            size_t len = strlen(rcvmsg);
            send(t_data->cfd, rcvmsg, len, 0); // Send the received data
        }
        fclose(dataFile);

        rc = pthread_mutex_unlock(&dataMutex);
        if (rc != 0 ) {
            syslog(LOG_ERR, "pthread_mutex_unlock failed with %d", rc);
            close(t_data->cfd);
            close(t_data->sfd);
            closelog();
            fclose(dataFile);
            exit(-1);
        }
        // critical section end
    }
    // update complete flag
    t_data->t_complete = true;

    return NULL;
}

// Create thread, add to slist
int createConnectionThread(int cfd, int sfd, struct sockaddr_storage* their_addr) {
    int rc;
    slist_data_t* t_data = malloc(sizeof(slist_data_t));
    t_data->cfd = cfd;
    t_data->sfd = sfd;
    t_data->their_addr = their_addr;
    t_data->t_complete = false;
    rc = pthread_create(&t_data->t_id, NULL, processConnectionThread, t_data); 
    if (rc != 0) {
        syslog(LOG_ERR, "failed to create connection thread");
        return -1;
    }
    SLIST_INSERT_HEAD(&head, t_data, entries);
    return 0;
}

int main(int argc, char *argv[]) {

    // open syslog
    openlog("aesdsocket", LOG_PID, LOG_USER);

    SLIST_INIT(&head);
    slist_data_t *t_data, *tmp;
    int rc = pthread_mutex_init(&dataMutex, NULL);
    if ( rc != 0 ) {
        syslog(LOG_ERR, "Failed to initialize account mutex, error was %d", rc);
        closelog();
        exit(-1);
    }

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

    // Setup the timer
    setup_timer();
    
    // Loop until killed
    while (1) {
        addr_size = sizeof their_addr;
        cfd = -1;
        //char rcvmsg[MAX_MSG_SIZE];


        // Blocking accept
        if((cfd = accept(sfd, (struct sockaddr *)&their_addr, &addr_size)) < 0) {         
            syslog(LOG_ERR, "Error: recv on socket %d failed", cfd);
            close(sfd);
            closelog();
            exit(-1);
        }

        // Create the connection thread adds to the list
        if (createConnectionThread(cfd, sfd, &their_addr) < 0) {
            syslog(LOG_ERR, "Creating thread for client connection %d failed", cfd);
            exit(-1);
        }
        syslog(LOG_DEBUG, "Thread created successfully for client connection %d", cfd);

        // Check for completed threads and join
        SLIST_FOREACH_SAFE(t_data, &head, entries, tmp) {
            if (t_data->t_complete) {
                pthread_join(t_data->t_id, NULL);
                syslog(LOG_DEBUG, "Thread %lu for connection %d joined successfully", (unsigned long)t_data->t_id, cfd);
                SLIST_REMOVE(&head, t_data, slist_data_s, entries);
                free(t_data); // Free the removed node
            }
        }

        // NOT A SIGNAL SAFE!!!
        if (close_syslog_flag) {
            pthread_mutex_destroy(&dataMutex);
            if (timer_delete(timer_id) == -1) {
                syslog(LOG_ERR,"timer_delete failed");
            } else {
                syslog(LOG_DEBUG,"timer_delete successfully");
            }
            closelog();
            close_syslog_flag = 0;  // Reset the flag
            break;                  // DAEMON IS DONE.
        }
    }

    return 0;
}