/* 
 * Copyright (C) 2014-2019 fdns Authors
 *
 * This file is part of fdns project
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#include "fdns.h"

#include <grp.h>
#include <pwd.h>
//#include <sys/wait.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <seccomp.h>

void daemonize(void) {
	if (daemon(0, 0) == -1)
		errExit("daemon");
}

void chroot_drop_privs(const char *username) {
	struct stat s;
	int rv;
	assert(username);

	// find user/group id
	struct passwd *pw;
	if ((pw = getpwnam(username)) == 0) {
		fprintf(stderr, "Error: can't find user nobody\n");
		exit(1);
	}

	// check /run/fdns directory
	if (stat(PATH_RUN_FDNS, &s)) {
		fprintf(stderr, "Error: cannot find %s directory\n", PATH_RUN_FDNS);
		exit(1);
	}

	// chroot
	rv = chroot(PATH_RUN_FDNS);
	if (rv == -1)
		errExit("chroot");
	rv = chdir("/");
	if (rv == -1)
		errExit("chdir");

	// drop privs
	if (setgroups(0, NULL) < 0) {
		fprintf(stderr, "Error: failed to drop supplementary groups\n");
		exit(1);
	}
	if (setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0) {
		fprintf(stderr, "Error: failed  to switch  the user\n");
		exit(1);
	}
}

//*************************************************
// seccomp: worker process
//*************************************************
static uint32_t arch_token;	// system architecture as detected by libseccomp

static void trap_handler_worker(int sig, siginfo_t *siginfo, void *ucontext) {
	(void) ucontext;
	if (sig == SIGSYS) {
		fprintf(stderr, "Error: fdns worker process %d killed by seccomp - syscall %d", arg_id, siginfo->si_syscall);
		char *syscall_name = seccomp_syscall_resolve_num_arch(arch_token, siginfo->si_syscall);
		if (syscall_name)
			fprintf(stderr, " (%s)", syscall_name);
		fprintf(stderr, "\n");

		rlogprintf("Error: fdns worker process %d killed by seccomp - syscall %d (%s)\n", arg_id, siginfo->si_syscall, syscall_name);
		free(syscall_name);
	}
}

static char *syscall_list;
int seccomp_load_filter_list(void) {
	struct stat s;
	if (stat(PATH_ETC_WORKER_SECCOMP, &s) == -1)
		goto errout;

	syscall_list = malloc(s.st_size + 10);
	if (!syscall_list)
		errExit("malloc");
	memset(syscall_list, 0, s.st_size + 10);

	FILE *fp = fopen(PATH_ETC_WORKER_SECCOMP, "r");
	if (!fp)
		goto errout;

	if (fgets(syscall_list, s.st_size + 10, fp) == NULL)
		goto errout;
	char *tmp = strchr(syscall_list, '\n');
	if (tmp)
		*tmp = '\0';
	fclose(fp);
	return 1;

errout:
	fprintf(stderr, "Warning: cannot load seccomp filter %s\n", PATH_ETC_WORKER_SECCOMP);
	rlogprintf("Warning: cannot load seccomp filter %s\n", PATH_ETC_WORKER_SECCOMP);
	return 0;
}

void seccomp_worker(void) {
	char *tmp = syscall_list;

	arch_token = seccomp_arch_native();
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP);
	if (!ctx)
		goto errout;

	struct sigaction sa;
	sa.sa_sigaction = &trap_handler_worker;
	sa.sa_flags = SA_SIGINFO;
	sigfillset(&sa.sa_mask);	// mask all other signals during the handler execution
	if (sigaction(SIGSYS, &sa, NULL) == -1)
		fprintf(stderr, "Warning: cannot handle sigaction/SIGSYS\n");

	char *syscall = strtok(tmp, ",");
	while(syscall) {
		if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_syscall_resolve_name(syscall), 0) == -1)
			fprintf(stderr, "Warning: syscall %s not added\n", syscall);
		syscall = strtok(NULL, ",");
	}

	int rc = seccomp_load(ctx);
//seccomp_export_bpf(ctx, STDOUT_FILENO);
//seccomp_export_pfc(ctx, STDOUT_FILENO);
//	seccomp_release(ctx);
	if (rc)
		goto errout;

	return;

errout:
	fprintf(stderr, "Warning: cannot initialize seccomp\n");
	rlogprintf("Warning: cannot initialize seccomp\n");
}

