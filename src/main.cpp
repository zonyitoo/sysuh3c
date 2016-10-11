#include "eapauth.h"
#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include <string>
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

// we use a new function to parse argument instead of getopt_long, which will
// cause problem when your password include '-'.
namespace get_opt {

  int optind = 1;
  const char *optarg;

  bool check_opt(const char* opt) {
  	if (opt[0] != '-') {
  		return false;
  	}
  	else if (opt[1] != '-') {
  		if (strlen(opt) == 2)
  			return true;
  		else
  			return false;
  	}
  }

  bool process_arg(const char* optstring, const char* opt, char &opt_name, bool &has_arg) {
  	const char _opt = opt[1];
  	size_t length = strlen(optstring);
  	for (size_t i = 0; i < length; ++i) {
  		if (optstring[i] == _opt) {
  			opt_name = optstring[i];
  			if (i + 1 < length && optstring[i + 1] == ':')
  				has_arg = true;
  			else
  				has_arg = false;
  			return true;
  		}
  	}
  	opt_name = _opt;
  	return false;
  }

  int getopt(int argc, char* const* argv, const char* optstring) {
  	char argval;
  	bool has_arg;
  	if (optind == argc)
  		return -1;
  	if (check_opt(argv[optind])) {
  		if (process_arg(optstring, argv[optind], argval, has_arg)) {
  			optind++;
  			if (has_arg) {
  				optarg = argv[optind];
  				optind++;
  			}
  			return argval;
  		}
  		else {
  			optind = argc;
  			return argval;
  		}
  	}
  	else {
  		optind = argc;
  		return 0;
  	}
  }

}

int main(int argc, char *const argv[]) {

    if (geteuid() != 0) {
        cerr << "You have to run the program as root" << endl;
        exit(EXIT_FAILURE);
    }

    string name, password, iface("eth0");
    bool daemon = false;
    bool color = false;
    char argval;

    using get_opt::optarg;
    using get_opt::optind;
    using get_opt::getopt;
    
    while ((argval = getopt(argc, argv, "u:p:i:dhc")) != -1) {
        switch (argval) {
        case 'h':
            printf("Usage: sysuh3c [arg]\n"
                   "   -h       print this screen\n"
                   "   -u       user account\n"
                   "   -p       password\n"
                   "   -i       network interface (default eth0)\n"
                   "   -d       daemonize\n"
                   "   -c       colorize\n");
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

    EAPAuth authservice(name, password, iface);

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
