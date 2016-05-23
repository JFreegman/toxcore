/*
* netprof.h -- Implementation of the onion part of docs/Prevent_Tracking.txt
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

#ifndef NETPROF_H
#define NETPROF_H

#include <stdint.h>

#define MAX_PACKET_IDS 256

typedef struct Packet_Stats {
    unsigned long int total_sent_packets;
    unsigned long int total_recv_packets;
    unsigned long int total_sent_bytes;
    unsigned long int total_recv_bytes;

    /* keeps track of the number of packets we send and receive for each packet ID */
    unsigned long int packets_recv[MAX_PACKET_IDS];
    unsigned long int packets_sent[MAX_PACKET_IDS];

    /* Keeps track of total number of bytes sent and received for each packet type */
    unsigned long int packet_bytes_sent[MAX_PACKET_IDS];
    unsigned long int packet_bytes_recv[MAX_PACKET_IDS];
} Packet_Stats;

/* Record a packet. direction is 1 if packet is inbound, 0 otherwise. */
void netprof_record_packet(Packet_Stats *packet_stats, const uint8_t *data, uint16_t length, int direction);

/* Print a full report of Tox network traffic to stderr */
void netprof_report_stats(Packet_Stats *packet_stats);

#endif    /* NETPROF_H */
