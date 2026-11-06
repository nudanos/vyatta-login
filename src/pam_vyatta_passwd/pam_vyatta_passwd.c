/*
 * Copyright (c) 2021, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <jansson.h>

#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>
#include <security/pam_appl.h>

#include <vyatta-cfg/client/mgmt.h>

#define	VERIFY_PASSWORD	1
#define CHANGE_PASSWORD	2

static int password(pam_handle_t *pamh, struct passwd *pw,
		    const char *cur_pw, const char *new_pw,
		    unsigned int flag)
{
	struct configd_conn conn;
	struct configd_error err = {0};
	const char ns[] = "vyatta-system-login-v1";
	const char *name;
	json_t *payload;
	char *input, *result;

	/* This runs in the forked child, before the configd connection. */
	if ((geteuid() == 0 && setgroups(0, NULL) == -1) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1 ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
		pam_syslog(pamh, LOG_DEBUG,
			   "password - cannot assume user identity: %s", strerror(errno));
		return -1;
	}

	if (configd_open_connection(&conn) < 0) {
		pam_syslog(pamh, LOG_DEBUG,
			   "password - configd_open_connection() error: %s",
			   strerror(errno));
		return -1;
	}

	if (flag == VERIFY_PASSWORD && cur_pw) {
		name = "verify-password";
		payload = json_pack("{s:s}", "current-password", cur_pw);
	} else if (flag == CHANGE_PASSWORD && cur_pw && new_pw) {
		name = "change-password";
		payload = json_pack("{s:s,s:s}", "current-password", cur_pw,
				    "new-password", new_pw);
	} else {
		goto error;
	}
	if (!payload)
		goto error;
	input = json_dumps(payload, JSON_COMPACT);
	json_decref(payload);
	if (!input)
		goto error;
	result = configd_call_rpc(&conn, ns, name, input, &err);
	explicit_bzero(input, strlen(input));
	free(input);
	if (result == NULL) {
		pam_syslog(pamh, LOG_DEBUG,
			   "password - configd_call_rpc() error: %s",
			   strerror(errno));
		if (err.text && write(STDERR_FILENO, err.text,
				      strlen(err.text)) == -1) {
			pam_syslog(pamh, LOG_DEBUG,
				   "password - write() error: %s",
				   strerror(errno));
		}
		goto error;
	}
	free(result);
	configd_close_connection(&conn);
	return 0;
error:
	if (err.text)
		configd_error_free(&err);
	configd_close_connection(&conn);
	return -1;
}

static int user_password(pam_handle_t *pamh, const char *user,
			 struct passwd *pw, const char *cur_pw,
			 const char *new_pw, unsigned int flag)
{
	pid_t pid;

	pid = fork();
	if (pid == -1) {
		pam_syslog (pamh, LOG_DEBUG, "password - fork() error: %s",
			    strerror(errno));
		return PAM_SYSTEM_ERR;
	}
	if (pid > 0) {
		int status = 0;
		pid_t rc;

		while ((rc = waitpid(pid, &status, 0)) == -1 && errno == EINTR)
			;
		if (rc == (pid_t)-1) {
			pam_syslog(pamh, LOG_DEBUG,
				   "password - waitpid() error: %s",
				   strerror(errno));
			return PAM_SYSTEM_ERR;
		} else if (status != 0) {
			pam_syslog(pamh, LOG_DEBUG,
				   "password change failed for user %s",
				   user);
			return PAM_AUTHTOK_ERR;
		}
		return PAM_SUCCESS;
	} else {
		if (password(pamh, pw, cur_pw, new_pw, flag) != 0) {
			pam_syslog(pamh, LOG_DEBUG,
				   "password change failed for user %s",
				   user);
			_exit(1);
		}
		_exit(0);
	}
	return PAM_SYSTEM_ERR;
}

int
pam_sm_chauthtok(pam_handle_t *pamh, int pam_flags,
                    int argc __attribute__ ((unused)),
                    const char **argv __attribute__ ((unused)))
{
	const char *user;
	const void *newpw, *oldpw;
	struct passwd *pw;
	const char *new_pw, *cur_pw;
	char *resp[2] = {NULL, NULL};
	int ret;

	ret = pam_get_user(pamh, &user, NULL);
	if (ret != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_DEBUG, "password - user %s is unknown",
			   user);
		return ret;
	}
	pw = pam_modutil_getpwnam(pamh, user);
	if (pw == NULL) {
		pam_syslog(pamh, LOG_ERR,
			   "password - no passwd entry for user %s", user);
		return PAM_USER_UNKNOWN;
	}
	if (pam_flags & PAM_PRELIM_CHECK) {
		if (pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &resp[0],
				"%s", "Current password: ") != PAM_SUCCESS
				|| resp[0] == NULL) {
			pam_syslog (pamh, LOG_DEBUG,
				    "password - pam_prompt() error: %s",
				    strerror(errno));
			return PAM_AUTHTOK_ERR;
		}
		pam_set_item(pamh, PAM_OLDAUTHTOK, resp[0]);
		return user_password(pamh, user, pw, resp[0], NULL,
				     VERIFY_PASSWORD);
	}
	if (!(pam_flags & PAM_UPDATE_AUTHTOK) ||
	    pam_get_item(pamh, PAM_AUTHTOK, &newpw) != PAM_SUCCESS || !newpw)
		return PAM_AUTHTOK_ERR;
	new_pw = (const char *)newpw;
	if (pam_get_item(pamh, PAM_OLDAUTHTOK, &oldpw) != PAM_SUCCESS || !oldpw) {
		pam_syslog (pamh, LOG_DEBUG,
			    "password - pam_get_item() on OLDAUTHTOK error: %s",
			    strerror(errno));
		return PAM_AUTHTOK_ERR;
	}
	cur_pw = (const char *)oldpw;
	return user_password(pamh, user, pw, cur_pw, new_pw,
			     CHANGE_PASSWORD);
}
