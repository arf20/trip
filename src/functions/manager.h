/*

    trip: Modern TRIP LS implementation
    Copyright (C) 2025 arf20 (Ángel Ruiz Fernandez)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/

#ifndef _MANAGER_H
#define _MANAGER_H

#include <netinet/in.h>


typedef struct {
    pthread_t   manager_thread;
    int         manager_fd;

    peer_t     *manager_peers;
    size_t      manager_peers_size;
    session_t  *manager_sessions;
    size_t      manager_sessions_size;
} manager_t;


manager_t *manager_new(struct sockaddr_in6 listen_addr, uint16_t listen_port,
    const peer_t *peers, size_t peers_size);

void manager_destroy();


#endif /* _MANAGER_H */

