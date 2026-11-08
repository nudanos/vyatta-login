#!/usr/bin/make -f

SRCDIR		:= pam_vyatta_passwd
MY_CFLAGS	:= -fPIC
MY_CFLAGS	+= -Wall -Wextra -Werror

CFLAGS += $(MY_CFLAGS)

LDLIBS  += -lvyatta-util
LDLIBS  += -lvyatta-config
LDLIBS  += -ljansson
LDLIBS  += -lpam

LDFLAGS	+= -shared
SRC	:= $(SRCDIR)/pam_vyatta_passwd.c
OBJ	:= $(SRCDIR)/pam_vyatta_passwd.o

TARGET_LIB	:= $(SRCDIR)/pam_vyatta_passwd.so
PAM_MODULE_DIR ?= /usr/lib/security

all: $(TARGET_LIB)

$(TARGET_LIB): $(OBJ)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(OBJ) -o $(TARGET_LIB) $(LDFLAGS) $(LDLIBS)

%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

install: $(TARGET_LIB)
	install -D -m644 $(TARGET_LIB) $(DESTDIR)$(PAM_MODULE_DIR)/pam_vyatta_passwd.so

clean:
	rm -f $(OBJ) $(TARGET_LIB)
