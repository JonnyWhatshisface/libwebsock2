/*
  callbacks.h

    Jonathan D. Hall - jhall@futuresouth.us
    Copyright 2015 Future South Technologies

    This file is part of libwebsock.

    libwebsock is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    libwebsock is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with libwebsock.  If not, see <http://www.gnu.org/licenses/>.

*/

#ifndef _callbacks_h
#define _callbacks_h

#include "core.h"
#include "websock.h"

int libwebsock_onopen_callback(libwebsock_client_state *state);
int libwebsock_onclose_callback(libwebsock_client_state *state);
int libwebsock_onmessage_callback(libwebsock_client_state *state, libwebsock_message *message);
int libwebsock_oncontrolframe_callback(libwebsock_client_state *state, libwebsock_frame *frame);

#endif /* callbacks_h */
