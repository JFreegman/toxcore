/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/*
 * An implementation of massive text only group chats.
 */

#ifndef GROUP_CHATS_H
#define GROUP_CHATS_H

#include <stdbool.h>
#include <stdint.h>

#include "TCP_connection.h"
#include "group_announce.h"
#include "group_common.h"
#include "group_connection.h"
#include "logger.h"

#define GC_PING_TIMEOUT 12
#define GC_SEND_IP_PORT_INTERVAL (GC_PING_TIMEOUT * 5)
#define GC_CONFIRMED_PEER_TIMEOUT (GC_PING_TIMEOUT * 6 + 10)
#define GC_UNCONFIRMED_PEER_TIMEOUT GC_PING_TIMEOUT

#define GC_JOIN_DATA_LENGTH (ENC_PUBLIC_KEY_SIZE + CHAT_ID_SIZE)

/* Group topic lock states. */
typedef enum Group_Topic_Lock {
    TL_ENABLED  = 0x00,  // Only the Founder and moderators may set the topic
    TL_DISABLED = 0x01,  // Anyone except Observers may set the topic
} Group_Topic_Lock;

/* Group moderation events. */
typedef enum Group_Moderation_Event {
    MV_KICK      = 0x00,  // A peer has been kicked
    MV_OBSERVER  = 0x01,  // A peer has been demoted to Observer
    MV_USER      = 0x02,  // A peer has been demoted or promoted to User
    MV_MOD       = 0x03,  // A peer has been promoted to or demoted from Moderator
} Group_Moderation_Event;

/* Messenger level group invite types */
typedef enum Group_Invite_Message_Type {
    GROUP_INVITE              = 0x00,  // Peer has initiated an invite
    GROUP_INVITE_ACCEPTED     = 0x01,  // Peer has accepted the invite
    GROUP_INVITE_CONFIRMATION = 0x02,  // Peer has confirmed the accepted invite
} Group_Invite_Message_Type;

typedef enum Group_Peer_Status {
    GS_NONE    = 0x00,
    GS_AWAY    = 0x01,
    GS_BUSY    = 0x02,
} Group_Peer_Status;

/**
 * Group save connection state.
 *
 * Used to determine whether or not a group should auto-connect the next time it's loaded.
 */
typedef enum Saved_GC_Conn_State {
    SGCS_DISCONNECTED = 0x00,  // The saved group is currently disconnected
    SGCS_CONNECTED    = 0x01,  // The saved group is currently connected
} Saved_GC_Conn_State;

/* Group join rejection types. */
typedef enum Group_Join_Rejected {
    GJ_GROUP_FULL       = 0x00,
    GJ_INVALID_PASSWORD = 0x01,
    GJ_INVITE_FAILED    = 0x02,
    GJ_INVALID          = 0x03,
} Group_Join_Rejected;

/* Group broadcast packet types */
typedef enum Group_Broadcast_Type {
    GM_STATUS          = 0x00,  // Peer changed their status
    GM_NICK            = 0x01,  // Peer changed their nickname
    GM_PLAIN_MESSAGE   = 0x02,  // Peer sent a normal message
    GM_ACTION_MESSAGE  = 0x03,  // Peer sent an action message
    GM_PRIVATE_MESSAGE = 0x04,  // Peer sent a private message
    GM_PEER_EXIT       = 0x05,  // Peer left the group
    GM_KICK_PEER       = 0x06,  // Peer was kicked from the group
    GM_SET_MOD         = 0x07,  // Peer was promoted to or demoted from Moderator role
    GM_SET_OBSERVER    = 0x08,  // Peer was demoted to or promoted from Observer role
} Group_Broadcast_Type;

/**
 * Group packet types.
 *
 * For a detailed spec, see docs/DHT_Group_Chats_Packet_Spec.md
 */
typedef enum Group_Packet_Type {
    /* lossy packets (ID 0 is reserved) */
    GP_PING                     = 0x01,
    GP_MESSAGE_ACK              = 0x02,
    GP_INVITE_RESPONSE_REJECT   = 0x03,

    /* lossless packets */
    GP_KEY_ROTATION             = 0xf0,
    GP_TCP_RELAYS               = 0xf1,
    GP_CUSTOM_PACKET            = 0xf2,
    GP_BROADCAST                = 0xf3,
    GP_PEER_INFO_REQUEST        = 0xf4,
    GP_PEER_INFO_RESPONSE       = 0xf5,
    GP_INVITE_REQUEST           = 0xf6,
    GP_INVITE_RESPONSE          = 0xf7,
    GP_SYNC_REQUEST             = 0xf8,
    GP_SYNC_RESPONSE            = 0xf9,
    GP_TOPIC                    = 0xfa,
    GP_SHARED_STATE             = 0xfb,
    GP_MOD_LIST                 = 0xfc,
    GP_SANCTIONS_LIST           = 0xfd,
    GP_FRIEND_INVITE            = 0xfe,
    GP_HS_RESPONSE_ACK          = 0xff,
} Group_Packet_Type;

/* Lossless message acknowledgement types. */
typedef enum Group_Message_Ack_Type {
    GR_ACK_RECV    = 0x00,  // indicates a message has been received
    GR_ACK_REQ     = 0x01,  // indicates a message needs to be re-sent
} Group_Message_Ack_Type;

/* Returns the GC_Connection object associated with `peer_number`.
 * Returns null if peer_number does not designate a valid peer.
 */
GC_Connection *get_gc_connection(const GC_Chat *chat, int peer_number);

/* Returns the jenkins hash of a 32 byte public encryption key. */
uint32_t gc_get_pk_jenkins_hash(const uint8_t *public_key);

/* Check if peer with the public encryption key is in peer list.
 *
 * Returns the peer number if peer is in the peer list.
 * Returns -1 if peer is not in the peer list.
 *
 * If `confirmed` is true the peer number will only be returned if the peer is confirmed.
 */
int get_peer_number_of_enc_pk(const GC_Chat *chat, const uint8_t *public_enc_key, bool confirmed);

/* Encrypts `data` of size `length` using the peer's shared key and a new nonce.
 *
 * Adds encrypted header consisting of: packet type, message_id (only for lossless packets).
 * Adds plaintext header consisting of: packet identifier, self public encryption key, nonce.
 *
 * Return length of encrypted packet on success.
 * Return -1 if plaintext length is invalid.
 * Return -2 if malloc fails.
 * Return -3 if encryption fails.
 */
int group_packet_wrap(const Logger *log, const uint8_t *self_pk, const uint8_t *shared_key, uint8_t *packet,
                      uint32_t packet_size, const uint8_t *data, uint32_t length, uint64_t message_id,
                      uint8_t gp_packet_type, uint8_t net_packet_type);

/* Packs group info for `chat` into `temp`. */
void gc_pack_group_info(const GC_Chat *chat, Saved_Group *temp);

/* Sends a plain message or an action, depending on type.
 *
 * `length` must not exceept MAX_GC_MESSAGE_SIZE and must not be equal to zero.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the message pointer is NULL or length is zero.
 * Returns -3 if the message type is invalid.
 * Returns -4 if the sender has the observer role.
 * Returns -5 if the packet fails to send.
 */
int gc_send_message(const GC_Chat *chat, const uint8_t *message, uint16_t length, uint8_t type);

/* Sends a private message to peer_id.
 *
 * `length` must not exceept MAX_GC_MESSAGE_SIZE and must not be equal to zero.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the message pointer is NULL or length is zero.
 * Returns -3 if the peer_id is invalid.
 * Returns -4 if the message type is invalid.
 * Returns -5 if the sender has the observer role.
 * Returns -6 if the packet fails to send.
 */
int gc_send_private_message(const GC_Chat *chat, uint32_t peer_id, uint8_t type, const uint8_t *message,
                            uint16_t length);

/* Sends a custom packet to the group. If lossless is true, the packet will be lossless.
 *
 * `length` must not exceept MAX_GC_MESSAGE_SIZE and must not be equal to zero.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the message pointer is NULL or length is zero.
 * Returns -3 if the sender has the observer role.
 */
int gc_send_custom_packet(const GC_Chat *chat, bool lossless, const uint8_t *data, uint32_t length);

/* Toggles ignore for peer_id.
 *
 * Returns 0 on success.
 * Returns -1 if the peer_id is invalid.
 * Returns -2 if the caller attempted to ignore himself.
 */
int gc_toggle_ignore(const GC_Chat *chat, uint32_t peer_id, bool ignore);

/* Sets the group topic and broadcasts it to the group.
 *
 * If `length` is equal to zero or topic is null the topic will be unset.
 *
 * Returns 0 on success.
 * Returns -1 if the topic is too long (must be <= MAX_GC_TOPIC_LENGTH).
 * Returns -2 if the caller does not have the required permissions to set the topic.
 * Returns -3 if the packet cannot be created or signing fails.
 * Returns -4 if the packet fails
 */
int gc_set_topic(GC_Chat *chat, const uint8_t *topic, uint16_t length);

/* Copies the group topic to `topic`. If topic is null this function has no effect.
 *
 * Call `gc_get_topic_size` to determine the allocation size for the `topic` parameter.
 *
 * The data written to `topic` is equal to the data received by the last topic callback.
 */
void gc_get_topic(const GC_Chat *chat, uint8_t *topic);

/* Returns the topic length.
 *
 * The return value is equal to the `length` agument received by the last topic
 * callback.
 */
uint16_t gc_get_topic_size(const GC_Chat *chat);

/* Copies group name to `group_name`. If `group_name` is null this function has no effect.
 *
 * Call `gc_get_group_name_size` to determine the allocation size for the `group_name`
 * parameter.
 */
void gc_get_group_name(const GC_Chat *chat, uint8_t *group_name);

/* Returns the group name length. */
uint16_t gc_get_group_name_size(const GC_Chat *chat);

/* Copies the group password to password. If password is null this function has no effect.
 *
 * Call the `gc_get_password_size` function to determine the allocation size for
 * the `password` buffer.
 *
 * The data received is equal to the data received by the last password callback.
 */
void gc_get_password(const GC_Chat *chat, uint8_t *password);

/* Returns the group password length. */
uint16_t gc_get_password_size(const GC_Chat *chat);

/* Returns the group privacy state.
 *
 * The value returned is equal to the data receieved by the last privacy_state callback.
 */
Group_Privacy_State gc_get_privacy_state(const GC_Chat *chat);

/* Returns the group topic lock state.
 *
 * The value returned is equal to the data received by the last last topic_lock callback.
 */
Group_Topic_Lock gc_get_topic_lock_state(const GC_Chat *chat);

/* Returns the group peer limit.
 *
 * The value returned is equal to the data receieved by the last peer_limit callback.
 */
uint32_t gc_get_max_peers(const GC_Chat *chat);

/* Sets your own nick to `nick`.
 *
 * `length` cannot exceed MAX_GC_NICK_SIZE. if `length` is zero or `name` is a
 * null pointer the function call will fail.
 *
 * Returns 0 on success.
 * Returns -1 if group_number is invalid.
 * Returns -2 if the length is too long.
 * Returns -3 if the length is zero or nick is a NULL pointer.
 * Returns -4 if the nick is already taken.
 * Returns -5 if the packet fails to send.
 */
int gc_set_self_nick(const Messenger *m, int group_number, const uint8_t *nick, uint16_t length);

/* Copies your own name to `nick`. If `nick` is null this function has no effect. */
void gc_get_self_nick(const GC_Chat *chat, uint8_t *nick);

/* Return your own nick length.
 *
 * If no nick was set before calling this function it will return 0.
 */
uint16_t gc_get_self_nick_size(const GC_Chat *chat);

/* Returns your own group role. */
Group_Role gc_get_self_role(const GC_Chat *chat);

/* Return your own status. */
uint8_t gc_get_self_status(const GC_Chat *chat);

/* Returns your own peer id. */
uint32_t gc_get_self_peer_id(const GC_Chat *chat);

/* Copies self public key to `public_key`. If `public_key` is null this function has no effect.
 *
 * This key is permanently tied to our identity for `chat` until we explicitly
 * exit the group. This key is the only way for other peers to reliably identify
 * us across client restarts.
 */
void gc_get_self_public_key(const GC_Chat *chat, uint8_t *public_key);

/* Copies nick designated by `peer_id` to `name`.
 *
 * Call `gc_get_peer_nick_size` to determine the allocation size for the `name` parameter.
 *
 * The data written to `name` is equal to the data received by the last nick_change callback.
 *
 * Returns 0 on success.
 * Returns -1 if peer_id is invalid.
 */
int gc_get_peer_nick(const GC_Chat *chat, uint32_t peer_id, uint8_t *name);

/* Returns the length of the nick for the peer designated by `peer_id`.
 * Returns -1 if peer_id is invalid.
 *
 * The value returned is equal to the `length` argument received by the last
 * nick_change callback.
 */
int gc_get_peer_nick_size(const GC_Chat *chat, uint32_t peer_id);

/* Copies peer_id's public key to `public_key`.
 *
 * This key is permanently tied to the peer's identity for `chat` until they explicitly
 * exit the group. This key is the only way for to reliably identify the given peer
 * across client restarts.
 *
 * `public_key` shold have room for at least ENC_PUBLIC_KEY_SIZE bytes.
 *
 * Returns 0 on success.
 * Returns -1 if peer_id is invalid or doesn't correspond to a valid peer connection.
 * Returns -2 if `public_key` is null.
 */
int gc_get_peer_public_key_by_peer_id(const GC_Chat *chat, uint32_t peer_id, uint8_t *public_key);

/* Gets the connection status for peer associated with `peer_id`.
 *
 * Returns 2 if we have a direct (UDP) connection with a peer.
 * Returns 1 if we have an indirect (TCP) connection with a peer.
 * Returns 0 if peer_id is invalid or corresponds to ourselves.
 *
 * Note: Return values must correspond to Tox_Connection enum in API.
 */
unsigned int gc_get_peer_connection_status(const GC_Chat *chat, uint32_t peer_id);

/* Sets the caller's status to `status`.
 *
 * Returns 0 on success.
 * Returns -1 if the group_number is invalid.
 * Returns -2 if the packet failed to send.
 */
int gc_set_self_status(const Messenger *m, int group_number, Group_Peer_Status status);

/* Returns the status of peer designated by `peer_id`.
 * Returns (uint8_t) -1 on failure.
 *
 * The status returned is equal to the last status received through the status_change
 * callback.
 */
uint8_t gc_get_status(const GC_Chat *chat, uint32_t peer_id);

/* Returns the group role of peer designated by `peer_id`.
 * Returns (uint8_t)-1 on failure.
 *
 * The role returned is equal to the last role received through the moderation callback.
 */
uint8_t gc_get_role(const GC_Chat *chat, uint32_t peer_id);

/* Sets the role of peer_id. role must be one of: GR_MODERATOR, GR_USER, GR_OBSERVER
 *
 * Returns 0 on success.
 * Returns -1 if the group_number is invalid.
 * Returns -2 if the peer_id is invalid.
 * Returns -3 if caller does not have sufficient permissions for the action.
 * Returns -4 if the role assignment is invalid.
 * Returns -5 if the role failed to be set.
 * Returns -6 if the caller attempted to kick himself.
 */
int gc_set_peer_role(const Messenger *m, int group_number, uint32_t peer_id, Group_Role role);

/* Sets the group password and distributes the new shared state to the group.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * If `password` is null or `password_length` is 0 the password will be unset for the group.
 *
 * Returns 0 on success.
 * Returns -1 if the caller does not have sufficient permissions for the action.
 * Returns -2 if the password is too long.
 * Returns -3 if the packet failed to send.
 * Returns -4 if malloc failed.
 */
int gc_founder_set_password(GC_Chat *chat, const uint8_t *password, uint16_t password_length);

/* Sets the topic lock and distributes the new shared state to the group.
 *
 * When the topic lock is enabled, only the group founder and moderators may set the topic.
 * When disabled, all peers except those with the observer role may set the topic.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * Returns 0 on success.
 * Returns -1 if group_number is invalid.
 * Returns -2 if `topic_lock` is an invalid type.
 * Returns -3 if the caller does not have sufficient permissions for this action.
 * Returns -4 if the group is disconnected.
 * Returns -5 if the topic lock could not be set.
 * Returns -6 if the packet failed to send.
 */
int gc_founder_set_topic_lock(const Messenger *m, int group_number, Group_Topic_Lock topic_lock);

/* Sets the group privacy state and distributes the new shared state to the group.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * If an attempt is made to set the privacy state to the same state that the group is already
 * in, the function call will be successful and no action will be taken.
 *
 * Returns 0 on success.
 * Returns -1 if group_number is invalid.
 * Returns -2 if the caller does not have sufficient permissions for this action.
 * Returns -3 if the group is disconnected.
 * Returns -4 if the privacy state could not be set.
 * Returns -5 if the packet failed to send.
 */
int gc_founder_set_privacy_state(const Messenger *m, int group_number, Group_Privacy_State new_privacy_state);

/* Sets the peer limit to maxpeers and distributes the new shared state to the group.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * Returns 0 on success.
 * Returns -1 if the caller does not have sufficient permissions for this action.
 * Returns -2 if the peer limit could not be set.
 * Returns -3 if the packet failed to send.
 */
int gc_founder_set_max_peers(GC_Chat *chat, uint32_t max_peers);

/* Removes peer designated by `peer_id` from peer list and sends a broadcast instructing
 * all other peers to remove the peer from their peerlist as well.
 *
 * This function will not trigger the peer_exit callback for the caller.
 *
 * Returns 0 on success.
 * Returns -1 if the group_number is invalid.
 * Returns -2 if the peer_id is invalid.
 * Returns -3 if the caller does not have sufficient permissions for this action.
 * Returns -4 if the action failed.
 * Returns -5 if the packet failed to send.
 * Returns -6 if the caller attempted to kick himself.
 */
int gc_kick_peer(const Messenger *m, int group_number, uint32_t peer_id);

/* Copies the chat_id to dest. If dest is null this function has no effect.
 *
 * `dest` should have room for at least CHAT_ID_SIZE bytes.
 */
void gc_get_chat_id(const GC_Chat *chat, uint8_t *dest);


/* Group callbacks */
void gc_callback_message(const Messenger *m, gc_message_cb *function);
void gc_callback_private_message(const Messenger *m, gc_private_message_cb *function);
void gc_callback_custom_packet(const Messenger *m, gc_custom_packet_cb *function);
void gc_callback_moderation(const Messenger *m, gc_moderation_cb *function);
void gc_callback_nick_change(const Messenger *m, gc_nick_change_cb *function);
void gc_callback_status_change(const Messenger *m, gc_status_change_cb *function);
void gc_callback_topic_change(const Messenger *m, gc_topic_change_cb *function);
void gc_callback_peer_limit(const Messenger *m, gc_peer_limit_cb *function);
void gc_callback_privacy_state(const Messenger *m, gc_privacy_state_cb *function);
void gc_callback_topic_lock(const Messenger *m, gc_topic_lock_cb *function);
void gc_callback_password(const Messenger *m, gc_password_cb *function);
void gc_callback_peer_join(const Messenger *m, gc_peer_join_cb *function);
void gc_callback_peer_exit(const Messenger *m, gc_peer_exit_cb *function);
void gc_callback_self_join(const Messenger *m, gc_self_join_cb *function);
void gc_callback_rejected(const Messenger *m, gc_rejected_cb *function);

/* The main loop. Should be called with every Messenger iteration. */
void do_gc(GC_Session *c, void *userdata);

/* Returns a NULL pointer if fail.
 * Make sure that DHT is initialized before calling this
 */
GC_Session *new_dht_groupchats(Messenger *m);

/* Cleans up groupchat structures and calls gc_group_exit() for every group chat */
void kill_dht_groupchats(GC_Session *c);

/* Loads a previously saved group and attempts to join it.
 *
 * `save` is the packed group info.
 *
 * Returns group_number on success.
 * Returns -1 on failure.
 */
int gc_group_load(GC_Session *c, const Saved_Group *save, int group_number);

/* Creates a new group and adds it to the group sessions group array.
 *
 * The caller of this function has founder role privileges.
 *
 * The client should initiate its peer list with self info after calling this function, as
 * the peer_join callback will not be triggered.
 *
 * Return -1 if the nick or group name is too long.
 * Return -2 if the nick or group name is empty.
 * Return -3 if the the group object fails to initialize.
 * Return -4 if the group state fails to initialize.
 * Return -5 if the Messenger friend connection fails to initialize.
 */
int gc_group_add(GC_Session *c, Group_Privacy_State privacy_state, const uint8_t *group_name,
                 uint16_t group_name_length,
                 const uint8_t *nick, size_t nick_length);

/* Joins a group designated by `chat_id`.
 *
 * This function creates a new GC_Chat object, adds it to the chats array, and sends a DHT
 * announcement to find peers in the group associated with `chat_id`. Once a peer has been
 * found a join attempt will be initiated.
 *
 * If the group is not password protected password should be set to NULL and password_length should be 0.
 *
 * Return group_number on success.
 * Return -1 if the group object fails to initialize.
 * Return -2 if chat_id is NULL or a group with chat_id already exists in the chats array.
 * Return -3 if nick is too long.
 * Return -4 if nick is empty or nick length is zero.
 * Return -5 if there is an error setting the group password.
 * Return -6 if the Messenger friend connection fails to initialize.
 */
int gc_group_join(GC_Session *c, const uint8_t *chat_id, const uint8_t *nick, size_t nick_length, const uint8_t *passwd,
                  uint16_t passwd_len);

/* Disconnects from all peers in a group but saves the group state for later use.
 *
 * Return 0 on sucess.
 * Return -1 if the group handler object or chat object is null.
 * Return -2 if malloc fails.
 */
int gc_disconnect_from_group(const GC_Session *c, GC_Chat *chat);

/* Disconnects from all peers in a group and attempts to reconnect. All self
 * state and credentials are retained.
 *
 * Returns 0 on success.
 * Returns -1 if the group handler object or chat object is null.
 * Returns -2 if the Messenger friend connection fails to initialize.
 */
int gc_rejoin_group(GC_Session *c, GC_Chat *chat);

/* Joins a group using the invite data received in a friend's group invite. The invite is
 * only valid while the inviter is present in the group.
 *
 * Return group_number on success.
 * Return -1 if the invite data is malformed.
 * Return -2 if the group object fails to initialize.
 * Return -3 if nick is too long.
 * Return -4 if nick is empty or nick length is zero.
 * Return -5 if there is an error setting the password.
 * Return -6 if friend doesn't exist.
 * Return -7 if sending packet failed.
 */
int gc_accept_invite(GC_Session *c, int32_t friend_number, const uint8_t *data, uint16_t length, const uint8_t *nick,
                     size_t nick_length, const uint8_t *passwd, uint16_t passwd_len);

typedef int gc_send_group_invite_packet_cb(const Messenger *m, uint32_t friendnumber, const uint8_t *packet,
        size_t length);

/* Invites friend designated by `friendnumber` to chat.
 * Packet includes: Type, chat_id, TCP node or packed IP_Port.
 *
 * Return 0 on success.
 * Return -1 if friendnumber does not exist.
 * Return -2 on failure to create the invite data.
 * Return -3 if the packet fails to send.
 */
int gc_invite_friend(const GC_Session *c, GC_Chat *chat, int32_t friendnum,
                     gc_send_group_invite_packet_cb *send_group_invite_packet);

/* Leaves a group and sends an exit broadcast packet with an optional parting message.
 *
 * All group state is permanently lost, including keys and roles.
 *
 * Return 0 on success.
 * Return -1 if the parting message is too long.
 * Return -2 if the parting message failed to send.
 * Return -3 if the group instance failed delete.
 */
int gc_group_exit(GC_Session *c, GC_Chat *chat, const uint8_t *message, uint16_t length);

/* Returns the number of active groups in `c`. */
uint32_t gc_count_groups(const GC_Session *c);

/* Returns true if peer_number exists */
bool gc_peer_number_is_valid(const GC_Chat *chat, int peer_number);

/* Return group_number's GC_Chat pointer on success
 * Return NULL on failure
 */
GC_Chat *gc_get_group(const GC_Session *c, int group_number);

/* Sends a lossless message acknowledgement to peer associated with `gconn`.
 *
 * If `type` is GR_ACK_RECV we send a read-receipt for read_id's packet. If `type` is GR_ACK_REQ
 * we send a request for the respective id's packet.
 *
 * requests are limited to one per second per peer.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int gc_send_message_ack(const GC_Chat *chat, GC_Connection *gconn, uint64_t message_id, Group_Message_Ack_Type type);

/* Helper function for handle_gc_lossless_packet().
 *
 * Note: This function may modify the peer list and change peer numbers.
 *
 * Return 0 if packet is successfully handled.
 * Return -1 on failure.
 */
int handle_gc_lossless_helper(const GC_Session *c, GC_Chat *chat, uint32_t peer_number, const uint8_t *data,
                              uint16_t length, uint8_t packet_type, void *userdata);

/* Handles an invite accept packet.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int handle_gc_invite_accepted_packet(const GC_Session *c, int friend_number, const uint8_t *data, uint32_t length);

/* Return true if `chat_id` is not present in our group sessions array.
 *
 * `length` must be at least CHAT_ID_SIZE bytes in length.
 */
bool group_not_added(const GC_Session *c, const uint8_t *chat_id, uint32_t length);

/* Handles an invite confirmed packet.
 *
 * Return 0 on success.
 * Return -1 if length is invalid.
 * Return -2 if data contains invalid chat_id.
 * Return -3 if data contains invalid peer info.
 * Return -4 if `friend_number` does not designate a valid friend.
 * Return -5 if data contains invalid connection info.
 */
int handle_gc_invite_confirmed_packet(const GC_Session *c, int friend_number, const uint8_t *data, uint32_t length);

/* Returns the group designated by `public_key`.
 * Returns null if group does not exist.
 */
GC_Chat *gc_get_group_by_public_key(const GC_Session *c, const uint8_t *public_key);

/* Attempts to add peers from `announces` to our peer list and initiate an invite request.
 *
 * Returns the number of peers added on success.
 * Returns -1 on failure.
 */
int gc_add_peers_from_announces(GC_Chat *chat, const GC_Announce *announces, uint8_t gc_announces_count);

#endif  // GROUP_CHATS_H

