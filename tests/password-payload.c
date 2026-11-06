#define _GNU_SOURCE
/* Exercise the real serializer through the configd transport boundary. */
#include <jansson.h>
#include "../src/pam_vyatta_passwd/pam_vyatta_passwd.c"

static const char *expected_current, *expected_new;
static unsigned int expected_flag;
static uid_t expected_uid;
static gid_t expected_gid;

int configd_open_connection(struct configd_conn *conn) { (void)conn; return geteuid() == expected_uid && getegid() == expected_gid ? 0 : -1; }
void configd_close_connection(struct configd_conn *conn) { (void)conn; }
void configd_error_free(struct configd_error *err) { free(err->text); }
char *configd_call_rpc(struct configd_conn *conn, const char *ns, const char *name,
                     const char *input, struct configd_error *err)
{
	json_t *payload = json_loads(input, JSON_REJECT_DUPLICATES, NULL);
	const char *current, *new;
	int matches;
	(void)conn;
	(void)err;
	if (!payload)
		return NULL;
	current = json_string_value(json_object_get(payload, "current-password"));
	new = json_string_value(json_object_get(payload, "new-password"));
	matches = strcmp(ns, "vyatta-system-login-v1") == 0 &&
		current && strcmp(current, expected_current) == 0 &&
		(expected_flag == VERIFY_PASSWORD ?
		 !new && strcmp(name, "verify-password") == 0 :
		 new && strcmp(new, expected_new) == 0 && strcmp(name, "change-password") == 0);
	json_decref(payload);
	return matches ? strdup("{}") : NULL;
}

static int check(struct passwd *pw, const char *current, const char *new, unsigned int flag)
{
	expected_uid = pw->pw_uid;
	expected_gid = pw->pw_gid;
	expected_current = current;
	expected_new = new;
	expected_flag = flag;
	return password(NULL, pw, current, new, flag) == 0;
}

int main(void)
{
	struct passwd pw = { .pw_uid = getuid(), .pw_gid = getgid() };
	char long_password[6001];
	int failures = 0;

	memset(long_password, 'a', sizeof(long_password) - 1);
	long_password[sizeof(long_password) - 1] = 0;
	if (!check(&pw, "old \"quoted\" \\n Ã©â€ºÂª", NULL, VERIFY_PASSWORD)) {
		fputs("verify RPC did not round-trip quotes/backslash/UTF-8\n", stderr);
		failures++;
	}
	if (!check(&pw, "old \"quoted\" \\n Ã©â€ºÂª", "new\t\"quoted\" \\ Ã¢ËœÆ’", CHANGE_PASSWORD)) {
		fputs("change RPC did not round-trip quotes/backslash/UTF-8/control bytes\n", stderr);
		failures++;
	}
	if (!check(&pw, long_password, long_password, CHANGE_PASSWORD)) {
		fputs("change RPC truncated long passwords\n", stderr);
		failures++;
	}
	if (geteuid() == 0) {
		struct passwd *nobody = getpwnam("nobody");
		pid_t child = fork();
		if (child == 0) _exit(nobody && check(nobody, "test", NULL, VERIFY_PASSWORD) ? 0 : 1);
		int status;
		if (child < 0 || waitpid(child, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status)) {
			fputs("transport did not use target effective identity\n", stderr);
			failures++;
		}
	}
	return failures != 0;
}
