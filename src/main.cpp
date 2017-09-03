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
#include <cstdlib>
#include <unistd.h>
#include <syslog.h>
using namespace std;
using namespace sysuh3c;

static int lockfd = -1;
static const char *lockfname = "/tmp/sysuh3c.pid";

static void interrupt_handler(int signo) {
    if (lockf(lockfd, F_ULOCK, 0) < 0) exit(EXIT_FAILURE);
    remove(lockfname);
    exit(EXIT_FAILURE);
}

bool is_daemon = false;

void daemonize() {
    if (getpid() == 1) return;
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);

    if (pid > 0) exit(EXIT_SUCCESS);

    setsid();

    close(fileno(stdin));
    close(fileno(stdout));
    close(fileno(stderr));

    umask(027);
    if (chdir("/") == -1) {
        perror("chdir");
        abort();
    }

    lockfd = open(lockfname, O_RDWR | O_CREAT, 0640);
    if (lockfd < 0) exit(EXIT_FAILURE);
    if (lockf(lockfd, F_TLOCK, 0) < 0) exit(EXIT_SUCCESS);

    char pidstr[128] = {0};
    sprintf(pidstr, "%d\n", getpid());
    if (write(lockfd, pidstr, strlen(pidstr)) == -1) {
        perror("write");
        abort();
    }

    openlog("sysuh3c", LOG_CONS, LOG_USER);

    signal(SIGCHLD, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGINT, interrupt_handler);
    signal(SIGTERM, interrupt_handler);

    is_daemon = true;
}

int main(int argc, char *const argv[]) {

    if (geteuid() != 0) {
        cerr << "You have to run the program as root" << endl;
        exit(EXIT_FAILURE);
    }

    struct option arglist[] = {
        {"help", no_argument, NULL, 'h'},
        {"user", required_argument, NULL, 'u'},
        {"password", required_argument, NULL, 'p'},
        {"iface", optional_argument, NULL, 'i'},
        {"method", optional_argument, NULL, 'm'},
        {"daemonize", no_argument, NULL, 'd'},
        {"colorize", no_argument, NULL, 'c'},
        {NULL, 0, NULL, 0}
    };

    string name, password, iface("eth0");
    eap_method method = EAP_METHOD_XOR;
    bool daemon = false;
    bool color = false;
    int argval = 0;
    // XXX: `getopt` and `getopt_long` seems to return an unsigned char value, which is different
    // to all the other systems!
    while ((argval = getopt_long(argc, argv, "u:p:i:m:dhc", arglist, NULL)) != -1 && argval != 255) {
        switch (argval) {
        case 'h':
            printf("Usage: sysuh3c [arg]\n"
                   "   -h --help       print this screen\n"
                   "   -u --user       user account\n"
                   "   -p --password   password\n"
                   "   -i --iface      network interface (default eth0)\n"
                   "   -m --method     EAP-MD5 CHAP method [xor/md5] (default xor)\n"
                   "   -d --daemonize  daemonize\n"
                   "   -c --colorize   colorize\n");
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
        case 'm':
            if (string(optarg) == "xor")
                method = EAP_METHOD_XOR;
            else if (string(optarg) == "md5")
                method = EAP_METHOD_MD5;
            else {
                cerr <<  "Argument Error! Method can only be xor or md5." << endl;
                return EXIT_FAILURE;
            }
            break;
        case 'd':
            daemon = true;
            break;
        case 'c':
            color = true;
            break;
        default:
            cout << "Argument Error. Unknown option." << endl;
            return EXIT_FAILURE;
        }
    }

    if (name.empty() || iface.empty()) {
        cerr <<  "Argument Error! No user name." << endl;
        return EXIT_FAILURE;
    }
    if (password.empty()) {
        char *pwd = getpass("Password: ");
        password = pwd;
    }

    EAPAuth authservice(name, password, iface, method);

    authservice.set_promote_listener([] (const string & msg) {
        string cpmsg(std::move(msg));
        cpmsg.erase(0, cpmsg.find_first_not_of("\t\n\r"));
        cpmsg.erase(cpmsg.find_last_not_of("\t\n\r") + 1);
        if (!cpmsg.empty()) {
            if (!is_daemon)
                cout << cpmsg << endl;
            else
                syslog(LOG_INFO, "%s", cpmsg.c_str());
        }
    });

    bool haslogin = false;
    int autoretry_count = 5;

    authservice.set_status_listener([&] (int8_t statno) {
        if (!is_daemon) {
            if (color)
                cout << "\033[01;" << 30 + statno << "m["
                     << name << ":" << iface << "] " << strstat(statno) << "\033[0m" << endl;
            else
                cout << "[" << name << ":" << iface << "] " << strstat(statno) << endl;
        }
        else {
            syslog(LOG_INFO, "[%s:%s] %s", name.c_str(), iface.c_str(),
                   strstat(statno).c_str());
        }

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
        if (fscanf(fp, "%d", &pid) == EOF) {
            perror("fscanf");
            abort();
        }
        int ret = kill(pid, SIGINT);
        fclose(fp);
    }

    while (autoretry_count --) {
        try {
            authservice.auth();
        }
        catch (const EAPAuthFailed &expt) {
            if (!haslogin)
                return EXIT_FAILURE;
        }
        catch (const EAPAuthException &expt) {
            cerr << expt.what() << endl;
        }
        sleep(2);
    }

    remove(lockfname);

    return 0;
}
