/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/socket.h>

#include "macro.h"

typedef struct Server Server;

int syslog_fixup_facility(int priority) _const_;

size_t syslog_parse_identifier(const char **buf, char **identifier, char **pid);

void server_forward_syslog(Server *s, int priority, const char *identifier, const char *message, const struct ucred *ucred, const struct timeval *tv);

void server_process_syslog_message(Server *s, const char *buf, size_t buf_len, const struct ucred *ucred, const struct timeval *tv, const char *label, size_t label_len);
int server_open_syslog_socket(Server *s, const char *syslog_socket);

void server_maybe_warn_forward_syslog_missed(Server *s);
