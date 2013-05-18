#include "eapauth.h"
#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <getopt.h>
#include <iostream>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstring>
using namespace std;

int lockfd = -1;
static const char *lockfname = "clih3c.lock";

static void interrupt_handler(int signo) {
    if (lockf(lockfd, F_ULOCK, 0) < 0) exit(EXIT_FAILURE);
    remove(lockfname);
    exit(EXIT_FAILURE);
}

void daemonize() {
    if (getpid() == 1) return;
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    
    if (pid > 0) exit(EXIT_SUCCESS);

    setsid();
    for (int i = getdtablesize(); i >= 0; -- i)
        close(i);
    int nullfd = open("/dev/null", O_RDWR);
    dup(nullfd);
    dup(nullfd);

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

int main(int argc, char **argv) {

    if (argc < 3) {
        printf("Usage: clih3c [arg]\n"
                "   -h --help       print this screen\n"
                "   -u --user       user account\n"
                "   -p --password   password\n"
                "   -i --iface      network interface (default eth0)\n"
                "   -d --daemonize  daemonize\n");
        exit(EXIT_FAILURE);
    }

    if (geteuid() != 0) {
        printf("You have to run the program as root\n");
        exit(EXIT_FAILURE);
    }
    
    struct option arglist[] = {
        {"help", no_argument, NULL, 'h'},
        {"user", required_argument, NULL, 'u'},
        {"password", required_argument, NULL, 'p'},
        {"iface", optional_argument, NULL, 'i'},
        {"daemonize", no_argument, NULL, 'd'},
        {NULL, 0, NULL, 0}
    };
    
    string name, password, iface("eth0");
    bool daemon = false;
    char argval;
    while ((argval = getopt_long(argc, argv, "u:p:i:d", arglist, NULL)) != -1) {
        switch (argval) {
            case 'h':
                printf("Usage: clih3c [arg]\n"
                        "   -h --help       print this screen\n"
                        "   -u --user       user account\n"
                        "   -p --password   password\n"
                        "   -i --iface      network interface (default eth0)\n"
                        "   -d --daemonize  daemonize\n");
                exit(EXIT_SUCCESS);
            case 'u':
                name = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 'i':
                iface = optarg;
                break;
            case 'd':
                daemon = true;
                break;
            default:
                printf("Argument Error. Unknown option.\n");
                exit(EXIT_FAILURE);
        }
    }
    
    EAPAuth authservice(name, password, iface);

    authservice.redirect_promote([] (const string& msg) {
        string cpmsg(std::move(msg));
        cpmsg.erase(0, cpmsg.find_first_not_of("\t\n\r"));
        cpmsg.erase(cpmsg.find_last_not_of("\t\n\r") + 1);
        if (!cpmsg.empty())
            cout << cpmsg << endl; 
    });
    
    bool haslogin = false;
    int autoretry_count = 5;

    authservice.set_status_changed_listener([&] (int8_t statno) {
        cout << strstat(statno) << endl;
        switch (statno) {
        case EAPAUTH_EAP_SUCCESS:
            haslogin = true;
            autoretry_count = 5;
            if (daemon)
                daemonize();
            break;
        case EAPAUTH_EAP_FAILURE:
            haslogin = false;
            break;
        }
    });

    FILE *fp = fopen(lockfname, "r");
    if (fp != nullptr) {
        pid_t pid;
        fscanf(fp, "%d", &pid);
        int ret = kill(pid, SIGINT);
        fclose(fp);
    }

    //daemonize();

    while (autoretry_count --) {
        try {
            authservice.auth();
            if (!haslogin) break;
        }
        catch (const EAPAuthException& expt) {
            cout << expt.what() << endl;
        }
        if (!haslogin) break;
        sleep(2);
    }
    return 0;
}
