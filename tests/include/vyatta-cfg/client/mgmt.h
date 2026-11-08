struct configd_conn { int unused; };
struct configd_error { char *text; };
int configd_open_connection(struct configd_conn *);
void configd_close_connection(struct configd_conn *);
void configd_error_free(struct configd_error *);
char *configd_call_rpc(struct configd_conn *, const char *, const char *,
                     const char *, struct configd_error *);
