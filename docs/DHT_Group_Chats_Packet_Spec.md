## DHT-Groupchats Packet Protocol Specification
This document specifies the use and structure of packets used by the DHT-Groupchats implementation.

All packet fields are considred mandatory unless flagged as `optional`. The minimum size of a lossless packet is 86 bytes, and a lossy packet 78 bytes. The maximum size of a packet is 1400 bytes.

## Table of Contents
- [Full Packet Structure](#headers)
- [Lossy Packet Payloads](#lossy_packets)
  - [PING (0x01)](#ping)
  - [MESSAGE_ACK (0x02)](#message_ack)
  - [INVITE_RESPONSE_REJECT (0x03)](#invite_response_reject)
- [Lossless Packet Payloads](#lossless_packets)
  - [TCP_RELAYS (0xf1)](#tcp_relays)
  - [CUSTOM_PACKET (0xf2)](#custom_packet)
  - [BROADCAST (0xf3)](#broadcast)
    - [STATUS](#status)
    - [NICK](#nick)
    - [PLAIN_MESSAGE](#plain_message)
    - [ACTION_MESSAGE](#action_message)
    - [PRIVATE_MESSAGE](#private_message)
    - [PEER_EXIT](#peer_exit)
    - [KICK_PEER](#kick_peer)
    - [SET_MOD](#set_mod)
    - [SET_OBSERVER](#set_observer)
  - [PEER_INFO_REQUEST (0xf4)](#peer_info_request)
  - [PEER_INFO_RESPONSE (0xf5)](#peer_info_response)
  - [INVITE_REQUEST (0xf6)](#invite_request)
  - [INVITE_RESPONSE (0xf7)](#invite_response)
  - [SYNC_REQUEST (0xf8)](#sync_request)
  - [SYNC_RESPONSE (0xf9)](#sync_response)
  - [TOPIC (0xfa)](#topic)
  - [SHARED_STATE (0xfb)](#shared_state)
  - [MOD_LIST (0xfc)](#mod_list)
  - [SANCTIONS_LIST (0xfd)](#sanctions_list)
  - [FRIEND_INVITE (0xfe)](#friend_invite)
  - [HS_RESPONSE_ACK (0xff)](#hs_response_ack)

<a name="headers"/>

## Full Packet Structure

#### Headers

###### Plaintext Header
`1 byte: toxcore packet identifier`  
`4 bytes: chat id hash`  
`32 bytes: sender permanent public encryption key`  
`24 bytes: nonce`  

###### Encrypted Header
`0-8 bytes: padding`  
`1 byte: group packet identifier`  
`1 byte: message id` (Optional: lossless only)  

#### Encrypted Payload
`variable bytes: payload`  

#### Description

The plaintext header contains a `toxcore packet identifier` which identifies the toxcore networking level packet type. These types are:  
`NET_PACKET_GC_HANDSHAKE = 0x5a`  
`NET_PACKET_GC_LOSSLESS = 0x5b`  
`NET_PACKET_GC_LOSSY = 0x5c`  

The `chat id hash` is a `jenkins_one_at_a_time_hash` of the group's chat ID. This is used to identify which group a particular message is intended for. The `sender public encryption key` is used to identify the peer who sent the packet, and the `nonce` is used for decryption.

The encrypted header contains between 0 and 8 bytes of empty padding, which is used to mitigate certain types of cryptography attacks. The `group packet identifier` is used to identify the type of group packet, and the `message id` is a unique packet identifier which is used for the lossless UDP implementation. 

The encrypted payload contains arbitrary data specific to the respective group packet identifier. The length may range from zero to the maximum packet size (minus the headers). These payloads will be the focus of the remainder of this document.

<a name="lossy_packets"/>

## Lossy Packet Payloads

<a name="ping"/>

### PING (0x01)

#### Structure

`2 bytes: peerlist checksum`  
`2 bytes: confirmed peer count`  
`2 bytes: shared state version`  
`2 bytes: sanctions credentials version`  
`2 bytes: topic version`  
`variable bytes: packed IP address and port of sender` (Optional)  

#### Description
Periodically sent to every confirmed peer in order to maintain peer connections, and to ensure the group state between peers are in sync. A peer is considered to be disconnected from the group after a ping packet has not been receieved over a period of time.

For further information on group syncing see: `docs/DHT-Group-Chats.md`

<a name="message_ack"/>

### MESSAGE_ACK (0x02)

#### Structure
`8 bytes: message_id`  
`1 byte: type`  

#### Description
Used to ensure that all lossless packets are successfully received and processed in sequential order as they were sent.

Ack types are defined by an enumerator beginning at zero as follows:
`GR_ACK_RECV = 0`  
`GR_ACK_REQ = 1`  

If the type is `GR_ACK_RECV`, this indicates that the packet with the given id has been received and successfully processed. If the type is `GR_ACK_REQ`, this indicates that the message with the given id should be sent again.

<a name="invite_response_reject"/>

### INVITE_RESPONSE_REJECT (0x03)

#### Structure
`1 bytes: type`  

#### Description
Alerts a peer that their invite request has been rejected. The reason for the rejection is specified by the `type` field.

Rejection types are defined by an enumerator beginning at zero as follows:  
`NICK_TAKEN = 0`  
`GROUP_FULL = 1`  
`INVALID_PASSWORD = 2`  
`INVITE_FAILED = 3`  

<a name="lossless_packets"/>

## Lossless Packet Payloads

<a name="tcp_relays"/>

### TCP_RELAYS (0xf1)

#### Structure
`variable bytes: packed tcp relays`

#### Description
Shares a list of TCP relays with a confirmed peer. Used to maintain a list of mutual TCP relays with other peers, which are used to maintain TCP connections when direct connections cannot be established.

This packet is sent to every confirmed peer whenever a new TCP relay is added to our list, or periodically when we presently have no shared TCP relays with a given peer.

<a name="custom_packet"/>

### CUSTOM_PACKET (0xf2)

#### Structure
`variable bytes: arbitrary data`

#### Description
Used to send arbitrary data to another peer. This packet may be used for client-side features.

<a name="broadcast"/>

### BROADCAST (0xf3)

#### Structure
`1 byte: type`  
`8 bytes: timestamp`  
`variable bytes: broadcast payload`  

#### Description
Broadcasts a message to all confirmed peers in a group (with the exception of `PRIVATE_MESSAGE`). The type of broadcast is specificed by the `type` field. 

Broadcast types are defined by an enumerator beginning at zero as follows:  

<a name="status"/>

##### STATUS (0x00)

###### Structure
`1 byte: status`  

###### Description
Indicates that a peer has changed their status. Statuses must be of type `TOX_USER_STATUS`.

<a name="nick"/>

##### NICK (0x01)

###### Structure
`variable bytes: nick`  

###### Description
Indicates that a peer has changed their nickname. A nick must be greater than 0 bytes, and may not exceed `TOX_MAX_NAME_LENGTH` bytes.

<a name="plain_message"/>

##### PLAIN_MESSAGE (0x02)

###### Structure
`variable bytes: arbitarary data`  

###### Description
Contains an arbitrary message. A plain message must be greater than 0 bytes, and may not exceed `TOX_MAX_MESSAGE_LENGTH` bytes.

<a name="action_message"/>

##### ACTION_MESSAGE (0x03)

###### Structure
`variable bytes: arbitarary data`  

###### Description
Contains an arbitrary action message. An action message must be greater than 0 bytes, and may not exceed `TOX_MAX_MESSAGE_LENGTH` bytes.

<a name="private_message"/>

##### PRIVATE_MESSAGE (0x04)

###### Structure
`variable bytes: arbitarary data`  

###### Description
Contains an arbitrary message which only the intended peer receives. A private message must be greater than 0 bytes, and may not exceed `TOX_MAX_MESSAGE_LENGTH` bytes.

<a name="peer_exit"/>

##### PEER_EXIT (0x05)

###### Structure
`variable bytes: arbitrary data` (Optional)  

###### Description
Indicates that a peer is leaving the group. Contains an optional part message which may not exceed `TOX_GROUP_MAX_PART_LENGTH`.

<a name="peer_kick"/>

##### PEER_KICK (0x06)

###### Structure
`32 bytes: public encryption key`  

###### Description
Indicates that the peer associated with the public encryption key has been kicked from the group by a moderator or the founder. This peer must be removed from the peer list.

<a name="set_mod"/>

##### SET_MOD (0x07)

###### Structure
`1 byte: flag`  
`32 bytes: public signature key`  

###### Description
Indicates that the peer associated with the public signature key has either been promoted to or demoted from the `Moderator` role by the group founder. If `flag` is non-zero, the peer should be promoted and added to the moderator list. Otherwise they should be demoted to the `User` role and removed from the moderator list.

<a name="set_observer"/>

##### SET_OBSERVER (0x08)

###### Structure
`1 byte: flag`  
`32 bytes: public encryption key`  
`32 bytes: public signature key`  
`137 bytes: one sanctions list entry` (Optional: only if `flag` is non-zero)  
`132 bytes: packed sanctions list credentials`  

###### Description
Indicates that the peer associated with the given public keys has either been demoted to or promoted from the `Observer` role by the group founder or a modreator. If `flag` is non-zero, the peer should be demoted and added to the sanctions list. Otherwise they should be promoted to the `User` role and removed from the sanctions list.

<a name="peer_info_request"/>

### PEER_INFO_REQUEST (0xf4)

#### Structure
`0 bytes: empty payload`  

#### Description
Requests a peer to send us information about themselves.

<a name="peer_info_response"/>

### PEER_INFO_RESPONSE (0xf5)

#### Structure
`32 bytes: group password`  
`2 bytes: name length`  
`128 bytes: name`  
`1 byte: status`  
`1 byte: role`  

#### Description
Supplies information about ourselves to a peer. This is sent as a response to a `PEER_INFO_REQUEST` or `HS_PEER_INFO_EXCHANGE` packet as part of the handshake protocol.

<a name="invite_request"/>

### INVITE_REQUEST (0xf6)

#### Structure
`2 bytes: name length`  
`name_length bytes: name`  
`32 bytes: group password`  

#### Description
Requests an invite to the group.

<a name="invite_response"/>

### INVITE_RESPONSE (0xf7)

#### Structure
`0 bytes: empty payload`  

#### Description
Alerts a peer who sent us a `INVITE_REQUEST` invite that their request has been validated, which informs them that they may continue to the next step in the handshake protocol. 

Before sending this packet we first attempt to validate the invite request. If validation fails, we instead send a packet of type `INVITE_RESPONSE_REJECT` in response, and remove the peer from our peer list.

<a name="sync_request"/>

### SYNC_REQUEST (0xf8)

#### Structure
`2 bytes: sync flags`  
`32 bytes: group password`  

#### Description
Asks a peer to send us state information about the group chat. The specific information being requested is specified via the `sync_flags` field.

`sync_flags` is a bitfield defined as a 16-bit unsigned integer which may have the bits set for the respective values depending on what information is being requested:  
`PEER_LIST = 0`  
`TOPIC = 2`  
`STATE = 4`  

<a name="sync_response"/>

### SYNC_RESPONSE (0xf9)

#### Structure
`32 bytes: public encryption key`  
`1 byte: ip_port_is_set flag`  
`1 byte: tcp relays count`  
`variable bytes: packed ip_port` (Optional: only if ip_port_is_set is non-zero)  
`variable bytes: packed tcp relays` (Optional: only if tcp relays count is > 0)  

#### Description
Sent as a response to a peer who made a sync request via the `SYNC_REQUEST` packet. This packet contains a single packed peer announce, which is a data structure that contains all of the information about a peer needed to initiate the handshake protocol via TCP relays, a direct connection, or both. 

If the `ip_port_is_set` flag is non-zero, the packet will contain a packed IP_Port of the peer associated with the given public key. If `tcp relays count` is greater than 0, the packet will contain a list of tcp relays that the peer associated with the given public key is connected to.

When responding to a sync request, one separate sync response will be sent for each peer in the peer list. All other requested group information is sent via its respective packet.

<a name="topic"/>

### TOPIC (0xfa)

#### Structure
`64 bytes: topic signature`  
`4 bytes: topic version`  
`2 bytes: topic length`  
`topic_length bytes: topic`  
`32 bytes: public signature key`  

#### Description
Contains a topic as well as information used to validate the topic. Sent when the topic changes, or in response to a `SYNC_REQUEST` in which the topic flag is set. A topic must be greater than 0 bytes in length, and may not exceed `TOX_GROUP_MAX_TOPIC_LENGTH` bytes.

For further information on topic validation see: `docs/DHT-Group-Chats.md`

<a name="shared_state"/>

### SHARED_STATE (0xfb)

#### Structure
`64 bytes: shared state signature`  
`4 bytes: shared state version`  
`64 bytes: founder extended public key`  
`4 bytes: peer limit`  
`2 bytes: group name length`  
`48 bytes: group name`  
`1 byte: privacy state`  
`2 bytes: group password length`  
`32 bytes: group password`  
`32 bytes: moderation list sha256 hash`  
`1 byte: topic lock state`  

#### Description
Contains information about the group shared state. Sent to all peers by the group founder whenever the shared state has changed. Also sent in response to a `SYNC_REQUEST` in which the `state` flag is set.

For further information on shared state validation see: `docs/DHT-Group-Chats.md`

<a name="mod_list"/>

### MOD_LIST (0xfc)

#### Structure
`2 bytes: number of moderator list entries`  
`variable bytes: moderator list`  

#### Description
Contains information about the moderator list, including the number of moderators and a list of public signature keys of all current moderators. Sent to all peers by the group founder after the moderator list has been modified. Also sent in response to a `SYNC_REQUEST` in which the `state` flag is set.

The `moderator list` is comprised of a series of 32 byte public signature keys.

This packet must always be sent after a `SHARED_STATE` packet, as the moderator list is validated using data contained within the shared state. For further information on moderator list validation see: `docs/DHT-Group-Chats.md`

<a name="sanctions_list"/>

### SANCTIONS_LIST (0xfd)

#### Structure
`2 bytes: number of sanctions list entries`  
`variable bytes: sanctions list`  
`132 bytes: packed sanctions list credentials`  

###### Sanctions list entry
` 1 byte: type`  
`32 bytes: public signature key`  
`8 bytes: timestamp`  
`32 bytes: public encryption key`  
`64 bytes: signature`  

###### Sanctions credentials
`4 bytes: version`  
`32 bytes: sha256 hash`  
`32 bytes: public signature key`  
`64 bytes: signature`  

#### Description
Contains information about the sanctions list, including the number of entries, the sanctions list, and the credentials needed to validate the sanctions list.

Sanctions types are defined as an enumerator beginning at zero as follows:  
`OBSERVER = 0`

During a sync response, this packet must be sent after a `MOD_LIST` packet, as the sanctions list is validated using the moderator list. For further information on sanctions list validation see: `docs/DHT-Group-Chats.md`

<a name="friend_invite"/>

### FRIEND_INVITE (0xfe)

#### Structure
`1 byte: type`  

#### Description
Used to initiate or respond to a group invite to or from an existing friend. The invite action is specified by the `type` field.

Invite types are defined as an enumerator beginning at zero as follows:  
`GROUP_INVITE = 0`  
`GROUP_INVITE_ACCEPTED = 1`  
`GROUP_INVITE_CONFIRMATION = 2`  

<a name="hs_response_ack"/>

### HS_RESPONSE_ACK (0xff)

#### Structure
`0 bytes: empty payload`  

#### Description
Used to send acknowledgement that a lower level toxcore `NET_PACKET_GC_HANDSHAKE` packet has been received, which is the first step in the group handshake protocol. This packet will initiate an invite request via the `INVITE_REQUEST` packet.
