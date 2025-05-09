/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "fdset.h"

typedef struct Server Server;
typedef struct StdoutStream StdoutStream;

int server_open_stdout_socket(Server *s, const char *stdout_socket);
int server_restore_streams(Server *s, FDSet *fds);

StdoutStream* stdout_stream_free(StdoutStream *s);
int stdout_stream_install(Server *s, int fd, StdoutStream **ret);
void stdout_stream_terminate(StdoutStream *s);
void stdout_stream_send_notify(StdoutStream *s);
