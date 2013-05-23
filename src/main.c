/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  clih3c main
 *
 *        Version:  1.0
 *        Created:  2013年05月24日 02时49分52秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Tyler Chung
 *   Organization:  SYSU
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include "eapauth.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>

int lockfd = -1;
static const char *lockfname = "clih3c.lock";

static void interrupt_handler(int signo) {
    if (lockf(lockfd, F_ULOCK, 0) < 0) exit(EXIT_FAILURE);
    remove(lockfname);
    exit(EXIT_SUCCESS);
}

void daemonize() {
    if (getpid() == 1) return;
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    
    if (pid > 0) exit(EXIT_SUCCESS);

    setsid();

    freopen("/dev/null", "r", stdin);
    freopen("/dev/null", "w", stdout);
    freopen("/dev/null", "w", stderr);

    umask(027);
    chdir("/tmp");

    lockfd = open(lockfname, O_RDWR | O_CREAT, 0640);
    if (lockfd < 0) exit(EXIT_FAILURE);
    if (lockf(lockfd, F_TLOCK, 0) < 0) exit(EXIT_SUCCESS);

    char pidstr[128] = {0};
    sprintf(pidstr, "%d\n", getpid());
    write(lockfd, pidstr, strlen(pidstr));

    signal(SIGCHLD, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGINT, interrupt_handler);
}

_Bool haslogin = 0;
int autoretry_count = 5;
_Bool toDaemon = 0;

static void status_callback(int statno) {
    printf("%s\n", strstat(statno));
    switch (statno) {
        case EAPAUTH_EAP_SUCCESS:
            haslogin = 1;
            autoretry_count = 5;
            if (toDaemon)
                daemonize();
            break;
        case EAPAUTH_EAP_FAILURE:
            haslogin = 0;
            break;
    }
}

static struct option arglist[] = {
        {"help", no_argument, NULL, 'h'},
        {"user", required_argument, NULL, 'u'},
        {"password", required_argument, NULL, 'p'},
        {"iface", optional_argument, NULL, 'i'},
        {"daemonize", no_argument, NULL, 'd'},
        {NULL, 0, NULL, 0}
    };

static const char usage_str[] = "Usage: clih3c [arg]\n"
                "   -h --help       print this screen\n"
                "   -u --user       user account\n"
                "   -p --password   password\n"
                "   -i --iface      network interface (default eth0)\n"
                "   -d --daemonize  daemonize\n";


int main(int argc, char **argv) {

    if (argc < 3) {
        printf(usage_str);
        exit(EXIT_FAILURE);
    }

    if (geteuid() != 0) {
        printf("You have to run the program as root\n");
        exit(EXIT_FAILURE);
    }
    
    eapauth_t eapauth;

    char iface[] = "eth0";

    char argval;
    while ((argval = getopt_long(argc, argv, "u:p:i:d", arglist, NULL)) != -1) {
        switch (argval) {
            case 'h':
                printf(usage_str);
                exit(EXIT_SUCCESS);
            case 'u':
                strcpy(eapauth.name, optarg);
                break;
            case 'p':
                strcpy(eapauth.password, optarg);
                break;
            case 'i':
                strcpy(iface, optarg);
                break;
            case 'd':
                toDaemon = 1;
                break;
            default:
                printf("Argument Error. Unknown option.\n");
                exit(EXIT_FAILURE);
        }
    }

    if (strlen(eapauth.name) == 0 || strlen(eapauth.password) == 0 || strlen(iface) == 0) {
        fprintf(stderr, "Argument Error. You should provide valid name and password.");
        return -1;
    }
    
    eapauth_init(&eapauth, iface);

    eapauth_set_status_listener(status_callback);

    FILE *fp = fopen(lockfname, "r");
    if (fp != NULL) {
        pid_t pid;
        fscanf(fp, "%d", &pid);
        kill(pid, SIGINT);
        fclose(fp);
    }

    while (autoretry_count --) {
        if (eapauth_auth(&eapauth) != 0) {
            fprintf(stderr, "eapauth_auth error");
        }
        if (!haslogin) break;
        sleep(2);
    }
    return 0;
}
