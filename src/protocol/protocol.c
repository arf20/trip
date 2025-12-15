/*

    trip: Modern TRIP LS implementation
    Copyright (C) 2023 arf20 (Ángel Ruiz Fernandez)

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

    protocol.c: protocol serialization/deserialzation, thread safe

*/

#include "protocol.h"

#include <string.h>


/* message OPEN */

runtime_error_t
new_msg_open(void *buff, size_t len,
    uint16_t hold, uint32_t itad, uint32_t id,
    const capinfo_routetype_t *capinfo_routetypes, size_t routetypes_size,
    capinfo_sendrecv_t capinfo_sendrecv)
{
    if (!buff)
        return ERROR_BUFF;

    size_t capinfo_routetypes_size = 0, capinfo_sendrecv_size = 0,
        opt_size = 0;

    if (capinfo_routetypes)
        capinfo_routetypes_size = sizeof(msg_open_opt_capinfo_t) +
            (sizeof(capinfo_routetype_t) * routetypes_size);
    if (capinfo_sendrecv != CAPINFO_SENDRECV_NULL)
        capinfo_sendrecv_size += sizeof(msg_open_opt_capinfo_t) +
            sizeof(capinfo_sendrecv_t);
    if (capinfo_routetypes || capinfo_sendrecv != CAPINFO_SENDRECV_NULL)
        opt_size = sizeof(msg_open_opt_t) + capinfo_routetypes_size +
            capinfo_sendrecv_size;
    size_t msg_size = sizeof(msg_t) + sizeof(msg_open_t) + opt_size;

    if (len < msg_size)
        return ERROR_BUFFLEN;

    if (hold != 0 && hold < 3)
        return ERROR_HOLD;

    if (itad == 0)
        return ERROR_ITAD;

    /* MSG { OPEN [{ OPT_CAPINFO { [CAPINFO_ROUTETYPE] | [CAPINFO_SENDRECV] } }] } */
    msg_t *msg = buff;
    msg->msg_len = msg_size - sizeof(msg_t);
    msg->msg_type = MSG_TYPE_OPEN;

    msg_open_t *msg_open = (msg_open_t*)msg->msg_val;
    msg_open->open_ver = 1;
    msg_open->open_reserved = 0;
    msg_open->open_hold = hold;
    msg_open->open_itad = itad;
    msg_open->open_id = id;
    msg_open->open_opts_len = msg_size - sizeof(msg_t) - sizeof(msg_open_t);

    void *end = msg_open->open_opts;
    if (capinfo_routetypes || capinfo_sendrecv != CAPINFO_SENDRECV_NULL)  {
        msg_open_opt_t *opt = end;
        opt->opt_type = OPEN_OPT_TYPE_CAPABILITY_INFO;
        opt->opt_len = opt_size - sizeof(msg_open_opt_t);
        end = &opt->opt_val;
    }

    if (capinfo_routetypes) {
        msg_open_opt_capinfo_t *opt_capinfo = end;
        opt_capinfo->cap_code = CAP_CODE_ROUTE_TYPES;
        opt_capinfo->cap_len = sizeof(capinfo_routetype_t) * routetypes_size;
        memcpy(opt_capinfo->cap_val, capinfo_routetypes, opt_capinfo->cap_len);
        end += capinfo_routetypes_size;
    }

    if (capinfo_sendrecv != CAPINFO_SENDRECV_NULL) {
        msg_open_opt_capinfo_t *opt_capinfo = end;
        opt_capinfo->cap_code = CAP_CODE_SEND_RECV;
        opt_capinfo->cap_len = sizeof(capinfo_sendrecv_t);
        *(capinfo_sendrecv_t*)&opt_capinfo->cap_val = capinfo_sendrecv;
        end += capinfo_sendrecv_size;
    }

    return msg_size;
}


/* message UPDATE
 * takes a list of attrs_size pointers to attributes that may be of type
 * msg_update_attr_t or msg_update_attr_lsencap_t
 */

runtime_error_t
new_msg_update(void *buff, size_t len,
    const msg_update_attr_t **attrs, size_t attrs_size)
{
    if (!buff)
        return ERROR_BUFF;

    if (len < sizeof(msg_t))
        return ERROR_BUFFLEN;

    msg_t *msg = buff;
    msg->msg_len = 0;
    msg->msg_type = MSG_TYPE_UPDATE;

    void *end = &msg->msg_val;
    for (size_t i = 0; i < attrs_size; i++) {
        const msg_update_attr_t *attr = attrs[i];
        size_t attrsize = IS_ATTR_FLAG_LSENCAP(attr->attr_flags) ?
            sizeof(msg_update_attr_lsencap_t) + attr->attr_len :
            sizeof(msg_update_attr_t) + attr->attr_len;

        if (len < end - buff + attrsize)
            return ERROR_BUFFLEN;

        memcpy(end, attr, attrsize);
        end += attrsize;
    }

    return end - buff;
}

runtime_error_t
new_attr_withdrawnroutes(void *buff, size_t len,
    int lsencap, uint32_t id, uint32_t seq,
    const route_t **routes, size_t routes_size)
{
    if (!buff)
        return ERROR_BUFF;

    size_t attr_size = lsencap ? sizeof(msg_update_attr_lsencap_t) :
        sizeof(msg_update_attr_t);

    for (size_t i = 0; i < routes_size; i++)
        attr_size += sizeof(route_t) + routes[i]->route_len;

    if (len < attr_size)
        return ERROR_BUFFLEN;

    void *end = buff;
    if (lsencap) {
        msg_update_attr_lsencap_t *attr = end;
        attr->attr_flags = ATTR_FLAG_WELL_KNOWN;
        attr->attr_type = ATTR_TYPE_WITHDRAWNROUTES;
        attr->attr_len = attr_size - sizeof(msg_update_attr_lsencap_t);
        attr->attr_id = id;
        attr->attr_seq = seq;
        end += sizeof(msg_update_attr_lsencap_t);
    } else {
        msg_update_attr_t *attr = end;
        attr->attr_flags = ATTR_FLAG_WELL_KNOWN | ATTR_FLAG_LSENCAP;
        attr->attr_type = ATTR_TYPE_WITHDRAWNROUTES;
        attr->attr_len = attr_size - sizeof(msg_update_attr_t);
        end += sizeof(msg_update_attr_t);
    }

    for (size_t i = 0; i < routes_size; i++) {
        size_t route_size = sizeof(route_t) + routes[i]->route_len;
        memcpy(end, routes[i], route_size);
        end += route_size;
    }

    return end - buff;
}

runtime_error_t
new_attr_reachableroutes(void *buff, size_t len,
    int lsencap, uint32_t id, uint32_t seq,
    const route_t **routes, size_t routes_size)
{
    if (!buff)
        return ERROR_BUFF;

    size_t attr_size = lsencap ? sizeof(msg_update_attr_lsencap_t) :
        sizeof(msg_update_attr_t);

    for (size_t i = 0; i < routes_size; i++)
        attr_size += sizeof(route_t) + routes[i]->route_len;

    if (len < attr_size)
        return ERROR_BUFFLEN;

    void *end = buff;
    if (lsencap) {
        msg_update_attr_lsencap_t *attr = end;
        attr->attr_flags = ATTR_FLAG_WELL_KNOWN;
        attr->attr_type = ATTR_TYPE_REACHABLEROUTES;
        attr->attr_len = attr_size - sizeof(msg_update_attr_lsencap_t);
        attr->attr_id = id;
        attr->attr_seq = seq;
        end += sizeof(msg_update_attr_lsencap_t);
    } else {
        msg_update_attr_t *attr = end;
        attr->attr_flags = ATTR_FLAG_WELL_KNOWN | ATTR_FLAG_LSENCAP;
        attr->attr_type = ATTR_TYPE_REACHABLEROUTES;
        attr->attr_len = attr_size - sizeof(msg_update_attr_t);
        end += sizeof(msg_update_attr_t);
    }

    for (size_t i = 0; i < routes_size; i++) {
        size_t route_size = sizeof(route_t) + routes[i]->route_len;
        memcpy(end, routes[i], route_size);
        end += route_size;
    }

    return end - buff;
}

/* server is a null-terminated C-string */
runtime_error_t
new_attr_nexthopserver(void *buff, size_t len,
    uint32_t next_itad, const char *server)
{
    if (!buff)
        return ERROR_BUFF;
    
    size_t server_len = strlen(server);
    
    if (len < sizeof(msg_update_attr_t) + sizeof(attr_nexthopserver_t) +
        server_len)
    {
        return ERROR_BUFFLEN;
    }

    msg_update_attr_t *attr = buff;
    attr->attr_flags = ATTR_FLAG_WELL_KNOWN;
    attr->attr_type = ATTR_TYPE_NEXTHOPSERVER;
    attr->attr_len = sizeof(attr_nexthopserver_t) + server_len;

    attr_nexthopserver_t *attr_val = (attr_nexthopserver_t*)attr->attr_val;
    attr_val->nexthopserver_itad = next_itad;
    attr_val->nexthopserver_serverlen = server_len;
    memcpy(attr_val->nexthopserver_server, server, server_len);

    return sizeof(msg_update_attr_t) + attr->attr_len;
}

runtime_error_t
new_attr_advertisementpath(void *buff, size_t len,
    const itadpath_t *path)
{
    if (!buff)
        return ERROR_BUFF;
    
    if (len < sizeof(msg_update_attr_t) + sizeof(attr_advertisementpath_t) +
        (sizeof(uint32_t) * path->itadpath_len))
    {
        return ERROR_BUFFLEN;
    }

    msg_update_attr_t *attr = buff;
    attr->attr_flags = ATTR_FLAG_WELL_KNOWN;
    attr->attr_type = ATTR_TYPE_ADVERTISEMENTPATH;
    attr->attr_len = sizeof(attr_advertisementpath_t) +
        (sizeof(uint32_t) * path->itadpath_len);
    memcpy(attr->attr_val, path, attr->attr_len);

    return sizeof(msg_update_attr_t) + attr->attr_len;
}

runtime_error_t
new_attr_routedpath(void *buff, size_t len,
    const itadpath_t *path)
{
    if (!buff)
        return ERROR_BUFF;
    
    if (len < sizeof(msg_update_attr_t) + sizeof(attr_routedpath_t) +
        (sizeof(uint32_t) * path->itadpath_len))
    {
        return ERROR_BUFFLEN;
    }

    msg_update_attr_t *attr = buff;
    attr->attr_flags = ATTR_FLAG_WELL_KNOWN;
    attr->attr_type = ATTR_TYPE_ROUTEDPATH;
    attr->attr_len = sizeof(attr_routedpath_t) +
        (sizeof(uint32_t) * path->itadpath_len);
    memcpy(attr->attr_val, path, attr->attr_len);

    return sizeof(msg_update_attr_t) + attr->attr_len;
}

runtime_error_t
new_attr_atomicaggregate(void *buff, size_t len)
{
    if (!buff)
        return ERROR_BUFF;
    
    if (len < sizeof(msg_update_attr_t))
        return ERROR_BUFFLEN;

    msg_update_attr_t *attr = buff;
    attr->attr_flags = ATTR_FLAG_WELL_KNOWN;
    attr->attr_type = ATTR_TYPE_ATOMICAGGREGATE;
    attr->attr_len = 0;

    return sizeof(msg_update_attr_t);
}

runtime_error_t
new_attr_localpref(void *buff, size_t len, uint32_t localpref)
{
    if (!buff)
        return ERROR_BUFF;
    
    if (len < sizeof(msg_update_attr_t) + sizeof(attr_localpref_t))
        return ERROR_BUFFLEN;

    msg_update_attr_t *attr = buff;
    attr->attr_flags = ATTR_FLAG_WELL_KNOWN;
    attr->attr_type = ATTR_TYPE_LOCALPREFERENCE;
    attr->attr_len = sizeof(attr_localpref_t);
    *(attr_localpref_t*)attr->attr_val = localpref;

    return sizeof(msg_update_attr_t) + attr->attr_len;
}

runtime_error_t
new_attr_med(void *buff, size_t len, uint32_t metric)
{
    if (!buff)
        return ERROR_BUFF;
    
    if (len < sizeof(msg_update_attr_t) + sizeof(attr_multiexitdisc_t))
        return ERROR_BUFFLEN;

    msg_update_attr_t *attr = buff;
    attr->attr_flags = ATTR_FLAG_WELL_KNOWN;
    attr->attr_type = ATTR_TYPE_MULTIEXITDISC;
    attr->attr_len = sizeof(attr_multiexitdisc_t);
    *(attr_multiexitdisc_t*)attr->attr_val = metric;

    return sizeof(msg_update_attr_t) + attr->attr_len;
}

runtime_error_t
new_attr_communities(void *buff, size_t len,
    const community_t *communities, size_t communities_size)
{
    if (!buff)
        return ERROR_BUFF;
    
    if (len < sizeof(msg_update_attr_t) +
        (sizeof(community_t) * communities_size))
    {
        return ERROR_BUFFLEN;
    }

    msg_update_attr_t *attr = buff;
    attr->attr_flags = ATTR_FLAG_WELL_KNOWN | ATTR_FLAG_TRANSITIVE;
    attr->attr_type = ATTR_TYPE_COMMUNITIES;
    attr->attr_len = sizeof(community_t) * communities_size;
    memcpy(attr->attr_val, communities, attr->attr_len);

    return sizeof(msg_update_attr_t) + attr->attr_len;
}

runtime_error_t
new_attr_itadtopology(void *buff, size_t len,
    uint32_t id, uint32_t seq,
    const uint32_t *itads, size_t itads_size)
{
    if (!buff)
        return ERROR_BUFF;
    
    if (len < sizeof(msg_update_attr_lsencap_t) +
        (sizeof(uint32_t) * itads_size))
    {
        return ERROR_BUFFLEN;
    }

    msg_update_attr_lsencap_t *attr = buff;
    attr->attr_flags = ATTR_FLAG_WELL_KNOWN | ATTR_FLAG_LSENCAP;
    attr->attr_type = ATTR_TYPE_ITADTOPOLOGY;
    attr->attr_len = sizeof(uint32_t) * itads_size;
    attr->attr_id = id;
    attr->attr_seq = seq;
    memcpy(attr->attr_val, itads, attr->attr_len);

    return sizeof(msg_update_attr_t) + attr->attr_len;
}

runtime_error_t
new_attr_convertedroute(void *buff, size_t len)
{
    if (!buff)
        return ERROR_BUFF;
    
    if (len < sizeof(msg_update_attr_t))
        return ERROR_BUFFLEN;

    msg_update_attr_t *attr = buff;
    attr->attr_flags = ATTR_FLAG_WELL_KNOWN;
    attr->attr_type = ATTR_TYPE_CONVERTEDROUTE;
    attr->attr_len = 0;

    return sizeof(msg_update_attr_t);
}

/* message KEEPALIVE */

runtime_error_t
new_msg_keepalive(void *buff, size_t len)
{
    if (!buff)
        return ERROR_BUFF;

    if (len < sizeof(msg_t))
        return ERROR_BUFFLEN;

    msg_t *msg = buff;
    msg->msg_len = 0;
    msg->msg_type = MSG_TYPE_KEEPALIVE;

    return sizeof(msg_t);
}


/* message NOTIFICATION */

runtime_error_t
new_msg_notification(void *buff, size_t len,
    uint8_t error_code, uint8_t error_subcode, size_t datalen, const void *data)
{
    if (!buff)
        return ERROR_BUFF;

    size_t msg_size = sizeof(msg_t) + sizeof(msg_notif_t) + datalen;
    if (len < msg_size)
        return ERROR_BUFFLEN;

    msg_t *msg = buff;
    msg->msg_len = sizeof(msg_notif_t) + datalen;
    msg->msg_type = MSG_TYPE_NOTIFICATION;

    msg_notif_t *msg_notif = (msg_notif_t*)msg->msg_val;
    msg_notif->notif_error_code = error_code;
    msg_notif->notif_error_subcode = error_subcode;
    memcpy(msg_notif->notif_data, data, datalen);

    return msg_size;
}

