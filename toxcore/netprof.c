/*
* netprof.c -- Implementation of the onion part of docs/Prevent_Tracking.txt
*
*  Copyright (C) 2013 Tox project All Rights Reserved.
*
*  This file is part of Tox.
*
*  Tox is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation, either version 3 of the License, or
*  (at your option) any later version.
*
*  Tox is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include "netprof.h"

/* Record a packet. direction is 1 if packet is inbound, 0 otherwise. */
void netprof_record_packet(Packet_Stats *packet_stats, const uint8_t *data, uint16_t length, int direction)
{
    if (length < 1) {
        return;
    }

    uint8_t packet_id = *data;

    if (packet_id >= MAX_PACKET_IDS) {
        return;
    }

    if (direction == 1) {
        ++packet_stats->total_recv_packets;
        ++packet_stats->packets_recv[packet_id];
        packet_stats->total_recv_bytes += length;
        packet_stats->packet_bytes_recv[packet_id] += length;
    } else if (direction == 0) {
        ++packet_stats->total_sent_packets;
        ++packet_stats->packets_sent[packet_id];
        packet_stats->total_sent_bytes += length;
        packet_stats->packet_bytes_sent[packet_id] += length;
    }
}

void netprof_report_stats(Packet_Stats *packet_stats)
{
    fprintf(stderr, "total packets sent: %lu\n", packet_stats->total_sent_packets);
    fprintf(stderr, "total packets recv: %lu\n", packet_stats->total_recv_packets);
    fprintf(stderr, "total bytes sent: %lu\n", packet_stats->total_sent_bytes);
    fprintf(stderr, "total bytes recv: %lu\n", packet_stats->total_recv_bytes);

    int i;

    for (i = 0; i < MAX_PACKET_IDS; ++i) {
        if (packet_stats->packets_sent[i] || packet_stats->packets_recv[i]) {
            fprintf(stderr, "--- packet kind: %d ---\n", i);
            fprintf(stderr, "packets sent: %lu (%.2f%%)\n", packet_stats->packets_sent[i],
                    (double) packet_stats->packets_sent[i] / packet_stats->total_sent_packets * 100);
            fprintf(stderr, "packets recv: %lu (%.2f%%)\n", packet_stats->packets_recv[i],
                    (double) packet_stats->packets_recv[i] / packet_stats->total_recv_packets * 100);
            fprintf(stderr, "bytes sent: %lu (%.2f%%)\n", packet_stats->packet_bytes_sent[i],
                    (double) packet_stats->packet_bytes_sent[i] / packet_stats->total_sent_bytes * 100);
            fprintf(stderr, "bytes recv: %lu (%.2f%%)\n\n", packet_stats->packet_bytes_recv[i],
                    (double) packet_stats->packet_bytes_recv[i] / packet_stats->total_recv_bytes * 100);
        }
    }
}
