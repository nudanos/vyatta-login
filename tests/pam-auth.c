#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int conversation(int count, const struct pam_message **messages,
                        struct pam_response **responses, void *password)
{
	*responses = calloc(count, sizeof(**responses));
	if (!*responses)
		return PAM_BUF_ERR;
	for (int i = 0; i < count; i++)
		if (messages[i]->msg_style == PAM_PROMPT_ECHO_OFF)
			(*responses)[i].resp = strdup(password);
	return PAM_SUCCESS;
}

int main(int argc, char **argv)
{
	pam_handle_t *pam = NULL;
	struct pam_conv conv = { conversation, argv[2] };
	int status;

	if (argc != 3 && argc != 4)
		return 2;
	status = pam_start("nudanos-lockout-test", argv[1], &conv, &pam);
	if (status != PAM_SUCCESS)
		return 2;
	status = pam_authenticate(pam, 0);
	if (status == PAM_SUCCESS && argc == 4)
		status = pam_acct_mgmt(pam, 0);
	printf("%d\n", status);
	pam_end(pam, status);
	return status == (argc == 4 ? PAM_NEW_AUTHTOK_REQD : PAM_SUCCESS) ? 0 : 1;
}
