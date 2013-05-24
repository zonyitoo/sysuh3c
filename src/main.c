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
#include <syslog.h>
#include "eaputils.h"
#include <stdarg.h>

static const char *lockfname = "/tmp/clih3c.lock";
int autoretry_count = 5;
_Bool toDaemon = 0;
_Bool isDaemon = 0;

static void signal_handler(int signo) {
    remove(lockfname);
    if (isDaemon)
        closelog();
    exit(EXIT_SUCCESS);
}

void daemonize() {
    int lockfd = -1;
    if (isDaemon) return;

    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    else if (pid > 0) exit(EXIT_SUCCESS);

    setsid();

    close(fileno(stdin));
    close(fileno(stdout));
    close(fileno(stderr));

    umask(027);
    chdir("/");

    lockfd = open(lockfname, O_RDWR | O_CREAT, 0640);
    if (lockfd < 0) exit(EXIT_FAILURE);
    if (lockf(lockfd, F_TLOCK, 0) < 0) exit(EXIT_SUCCESS);

    char pidstr[128] = {0};
    sprintf(pidstr, "%d\n", getpid());
    write(lockfd, pidstr, strlen(pidstr));

    openlog("clih3c", LOG_CONS, LOG_USER);

    signal(SIGCHLD, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    isDaemon = 1;
}

static void status_callback(int statno) {
    if (statno != EAPAUTH_EAP_RESPONSE) {
        if (isDaemon)
            syslog(LOG_INFO, "%s", strstat(statno));
        else
            printf("%s\n", strstat(statno));
    }
    switch (statno) {
        case EAPAUTH_EAP_SUCCESS:
            autoretry_count = 5;
            if (toDaemon)
                daemonize();
            break;
        case EAPAUTH_EAP_FAILURE:
            break;
    }
}

static void display_msg(int priority, const char *format, ...) {
    va_list arg;
    va_start(arg, format);
    if (isDaemon)
        syslog(priority, format, arg);
    else {
        fprintf(stderr, format, arg);
        fprintf(stderr, "\n");
    }
    va_end(arg);
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

    int ret;
    char iface[6] = "eth0";
    char argval;
    FILE *fp = NULL;

    if (argc < 3) {
        printf(usage_str);
        exit(EXIT_FAILURE);
    }

    if (geteuid() != 0) {
        printf("You have to run the program as root\n");
        exit(EXIT_FAILURE);
    }
    
    eapauth_t eapauth;

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
        exit(EXIT_FAILURE);
    }
    
    if (eapauth_init(&eapauth, iface) != 0)
        exit(EXIT_FAILURE);

    eapauth_set_status_listener(status_callback);
    eapauth_redirect_promote(display_msg);

    fp = fopen(lockfname, "r");
    if (fp != NULL) {
        pid_t pid;
        fscanf(fp, "%d", &pid);
        kill(pid, SIGINT);
        fclose(fp);
    }

    while (autoretry_count --) {
        ret = eapauth_auth(&eapauth);
        if (ret == EAPAUTH_ERR) 
            display_msg(LOG_ERR, "eapauth_auth error : %d", ret);
        else if (ret == EAPAUTH_FAIL)
            break;
        sleep(2);
    }

    if (isDaemon)
        closelog();
    return 0;
}
