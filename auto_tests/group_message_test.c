/*
 * Tests that we can invite a friend to a private group chat and exchange messages with them.
 * In addition, we spam many messages at once and ensure that they all arrive in the correct order.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "check_compat.h"

typedef struct State {
    uint32_t index;
    uint64_t clock;
    uint32_t peer_id;
    bool peer_joined;
    bool message_sent;
    bool message_received;
    bool private_message_received;
    size_t custom_packets_received;
    bool lossless_check;
    int last_msg_recv;
} State;

#include "run_auto_test.h"


#define NUM_GROUP_TOXES 2
#define MAX_NUM_MESSAGES 1000

#define TEST_MESSAGE "Where is it I've read that someone condemned to death says or thinks, an hour before his death, that if he had to live on some high rock, on such a narrow ledge that he'd only room to stand, and the ocean, everlasting darkness, everlasting solitude, everlasting tempest around him, if he had to remain standing on a square yard of space all his life, a thousand years, eternity, it were better to live so than to die at once. Only to live, to live and live! Life, whatever it may be!"
#define TEST_MESSAGE_LEN (sizeof(TEST_MESSAGE) - 1)

#define TEST_GROUP_NAME "Utah Data Center"
#define TEST_GROUP_NAME_LEN (sizeof(TEST_GROUP_NAME) - 1)

#define TEST_PRIVATE_MESSAGE "Don't spill yer beans"
#define TEST_PRIVATE_MESSAGE_LEN (sizeof(TEST_PRIVATE_MESSAGE) - 1)

#define TEST_CUSTOM_PACKET "Why'd ya spill yer beans?"
#define TEST_CUSTOM_PACKET_LEN (sizeof(TEST_CUSTOM_PACKET) - 1)

#define PEER0_NICK "Victor"
#define PEER0_NICK_LEN (sizeof(PEER0_NICK) - 1)

#define PEER1_NICK "George"
#define PEER1_NICK_LEN (sizeof(PEER1_NICK) - 1)

static void group_invite_handler(Tox *tox, uint32_t friend_number, const uint8_t *invite_data, size_t length,
                                 const uint8_t *group_name, size_t group_name_length, void *user_data)
{
    printf("invite arrived; accepting\n");
    TOX_ERR_GROUP_INVITE_ACCEPT err_accept;
    tox_group_invite_accept(tox, friend_number, invite_data, length, (const uint8_t *)PEER0_NICK, PEER0_NICK_LEN,
                            nullptr, 0, &err_accept);
    ck_assert(err_accept == TOX_ERR_GROUP_INVITE_ACCEPT_OK);
}

static void group_join_fail_handler(Tox *tox, uint32_t groupnumber, TOX_GROUP_JOIN_FAIL fail_type, void *user_data)
{
    printf("join failed: %d\n", fail_type);
}

static void group_peer_join_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, void *user_data)
{
    State *state = (State *)user_data;
    printf("peer %u joined, sending message\n", peer_id);
    state->peer_joined = true;
    state->peer_id = peer_id;
}

static void group_custom_packet_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, const uint8_t *data,
                                        size_t length, void *user_data)
{
    ck_assert_msg(length == TEST_CUSTOM_PACKET_LEN, "Failed to receive custom packet. Invalid length: %zu\n", length);

    char message_buf[TOX_MAX_CUSTOM_PACKET_SIZE + 1];
    memcpy(message_buf, data, length);
    message_buf[length] = 0;

    TOX_ERR_GROUP_PEER_QUERY q_err;
    size_t peer_name_len = tox_group_peer_get_name_size(tox, groupnumber, peer_id, &q_err);

    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(peer_name_len <= TOX_MAX_NAME_LENGTH);

    char peer_name[TOX_MAX_NAME_LENGTH + 1];
    tox_group_peer_get_name(tox, groupnumber, peer_id, (uint8_t *) peer_name, &q_err);
    peer_name[peer_name_len] = 0;

    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(memcmp(peer_name, PEER1_NICK, peer_name_len) == 0);

    TOX_ERR_GROUP_SELF_QUERY s_err;
    size_t self_name_len = tox_group_self_get_name_size(tox, groupnumber, &s_err);
    ck_assert(s_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(self_name_len <= TOX_MAX_NAME_LENGTH);

    char self_name[TOX_MAX_NAME_LENGTH + 1];
    tox_group_self_get_name(tox, groupnumber, (uint8_t *) self_name, &s_err);
    self_name[self_name_len] = 0;

    ck_assert(s_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(memcmp(self_name, PEER0_NICK, self_name_len) == 0);

    printf("%s sent custom packet to %s: %s\n", peer_name, self_name, message_buf);
    ck_assert(memcmp(message_buf, TEST_CUSTOM_PACKET, length) == 0);

    State *state = (State *)user_data;
    ++state->custom_packets_received;
}

static void group_message_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, TOX_MESSAGE_TYPE type,
                                  const uint8_t *message, size_t length, void *user_data)
{
    ck_assert_msg(length == TEST_MESSAGE_LEN, "Failed to receive message. Invalid length: %zu\n", length);

    char message_buf[TOX_MAX_MESSAGE_LENGTH + 1];
    memcpy(message_buf, message, length);
    message_buf[length] = 0;

    TOX_ERR_GROUP_PEER_QUERY q_err;
    size_t peer_name_len = tox_group_peer_get_name_size(tox, groupnumber, peer_id, &q_err);

    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(peer_name_len <= TOX_MAX_NAME_LENGTH);

    char peer_name[TOX_MAX_NAME_LENGTH + 1];
    tox_group_peer_get_name(tox, groupnumber, peer_id, (uint8_t *) peer_name, &q_err);
    peer_name[peer_name_len] = 0;

    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(memcmp(peer_name, PEER0_NICK, peer_name_len) == 0);

    TOX_ERR_GROUP_SELF_QUERY s_err;
    size_t self_name_len = tox_group_self_get_name_size(tox, groupnumber, &s_err);
    ck_assert(s_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(self_name_len <= TOX_MAX_NAME_LENGTH);

    char self_name[TOX_MAX_NAME_LENGTH + 1];
    tox_group_self_get_name(tox, groupnumber, (uint8_t *) self_name, &s_err);
    self_name[self_name_len] = 0;

    ck_assert(s_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(memcmp(self_name, PEER1_NICK, self_name_len) == 0);

    printf("%s sent message to %s: %s\n", peer_name, self_name, message_buf);
    ck_assert(memcmp(message_buf, TEST_MESSAGE, length) == 0);

    State *state = (State *)user_data;
    state->message_received = true;
}

static void group_private_message_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, TOX_MESSAGE_TYPE type,
        const uint8_t *message, size_t length, void *user_data)
{
    ck_assert_msg(length == TEST_PRIVATE_MESSAGE_LEN, "Failed to receive message. Invalid length: %zu\n", length);

    char message_buf[TOX_MAX_MESSAGE_LENGTH + 1];
    memcpy(message_buf, message, length);
    message_buf[length] = 0;

    TOX_ERR_GROUP_PEER_QUERY q_err;
    size_t peer_name_len = tox_group_peer_get_name_size(tox, groupnumber, peer_id, &q_err);

    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(peer_name_len <= TOX_MAX_NAME_LENGTH);

    char peer_name[TOX_MAX_NAME_LENGTH + 1];
    tox_group_peer_get_name(tox, groupnumber, peer_id, (uint8_t *) peer_name, &q_err);
    peer_name[peer_name_len] = 0;

    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(memcmp(peer_name, PEER1_NICK, peer_name_len) == 0);

    TOX_ERR_GROUP_SELF_QUERY s_err;
    size_t self_name_len = tox_group_self_get_name_size(tox, groupnumber, &s_err);
    ck_assert(s_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(self_name_len <= TOX_MAX_NAME_LENGTH);

    char self_name[TOX_MAX_NAME_LENGTH + 1];
    tox_group_self_get_name(tox, groupnumber, (uint8_t *) self_name, &s_err);
    self_name[self_name_len] = 0;

    ck_assert(s_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(memcmp(self_name, PEER0_NICK, self_name_len) == 0);

    printf("%s sent private action to %s: %s\n", peer_name, self_name, message_buf);
    ck_assert(memcmp(message_buf, TEST_PRIVATE_MESSAGE, length) == 0);

    State *state = (State *)user_data;
    ck_assert(type == TOX_MESSAGE_TYPE_ACTION);
    state->private_message_received = true;
}

static void group_message_handler_2(Tox *tox, uint32_t groupnumber, uint32_t peer_id, TOX_MESSAGE_TYPE type,
                                    const uint8_t *message, size_t length, void *user_data)
{
    State *state = (State *)user_data;

    ck_assert(state != nullptr);
    ck_assert(length > 0 && length <= TOX_MAX_MESSAGE_LENGTH);

    char c[TOX_MAX_MESSAGE_LENGTH + 1];
    memcpy(c, message, length);
    c[length] = 0;

    int n = strtol((const char *) c, nullptr, 10);

    ck_assert_msg(n == state->last_msg_recv + 1, "Expected %d, got %d", state->last_msg_recv + 1, n);
    state->last_msg_recv = n;

    // fprintf(stderr, "Got %d\n", state->last_msg_recv);

    if (state->last_msg_recv == MAX_NUM_MESSAGES) {
        state->lossless_check = true;
    }
}

static void group_message_test(Tox **toxes, State *state)
{
#ifndef VANILLA_NACL
    ck_assert_msg(NUM_GROUP_TOXES >= 2, "NUM_GROUP_TOXES is too small: %d", NUM_GROUP_TOXES);

    tox_callback_group_invite(toxes[1], group_invite_handler);
    tox_callback_group_join_fail(toxes[1], group_join_fail_handler);
    tox_callback_group_peer_join(toxes[1], group_peer_join_handler);
    tox_callback_group_join_fail(toxes[0], group_join_fail_handler);
    tox_callback_group_peer_join(toxes[0], group_peer_join_handler);
    tox_callback_group_message(toxes[0], group_message_handler);
    tox_callback_group_custom_packet(toxes[1], group_custom_packet_handler);
    tox_callback_group_private_message(toxes[1], group_private_message_handler);

    // tox0 makes new group.
    TOX_ERR_GROUP_NEW err_new;
    uint32_t group_number = tox_group_new(toxes[0], TOX_GROUP_PRIVACY_STATE_PRIVATE, (const uint8_t *)TEST_GROUP_NAME,
                                          TEST_GROUP_NAME_LEN, (const uint8_t *)PEER1_NICK, PEER1_NICK_LEN, &err_new);

    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);

    // tox0 invites tox1
    TOX_ERR_GROUP_INVITE_FRIEND err_invite;
    tox_group_invite_friend(toxes[0], group_number, 0, &err_invite);
    ck_assert(err_invite == TOX_ERR_GROUP_INVITE_FRIEND_OK);

    while (!state[0].message_received) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

        if (state[1].peer_joined && !state[1].message_sent) {
            TOX_ERR_GROUP_SEND_MESSAGE err_send;
            tox_group_send_message(toxes[1], group_number, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)TEST_MESSAGE,
                                   TEST_MESSAGE_LEN, &err_send);
            ck_assert(err_send == TOX_ERR_GROUP_SEND_MESSAGE_OK);
            state[1].message_sent = true;
        }
    }

    fprintf(stderr, "Sending private message...\n");

    // tox0 sends a private action to tox1
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE m_err;
    tox_group_send_private_message(toxes[0], group_number, state[0].peer_id, TOX_MESSAGE_TYPE_ACTION,
                                   (const uint8_t *)TEST_PRIVATE_MESSAGE, TEST_PRIVATE_MESSAGE_LEN, &m_err);
    ck_assert_msg(m_err == TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_OK, "%d", m_err);

    fprintf(stderr, "Sending custom packets...\n");

    // // tox0 sends a lossless and lossy custom packet to tox1
    TOX_ERR_GROUP_SEND_CUSTOM_PACKET c_err;
    tox_group_send_custom_packet(toxes[0], group_number, true, (const uint8_t *)TEST_CUSTOM_PACKET, TEST_CUSTOM_PACKET_LEN,
                                 &c_err);
    ck_assert_msg(c_err == TOX_ERR_GROUP_SEND_CUSTOM_PACKET_OK, "%d", c_err);

    tox_group_send_custom_packet(toxes[0], group_number, false, (const uint8_t *)TEST_CUSTOM_PACKET, TEST_CUSTOM_PACKET_LEN,
                                 &c_err);
    ck_assert_msg(c_err == TOX_ERR_GROUP_SEND_CUSTOM_PACKET_OK, "%d", c_err);

    while (!state[1].private_message_received && state[1].custom_packets_received < 2) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    }

    // tox0 spams messages to tox1
    fprintf(stderr, "Doing lossless packet test...\n");

    tox_callback_group_message(toxes[1], group_message_handler_2);
    iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

    state[1].last_msg_recv = -1;

    for (size_t i = 0; i <= MAX_NUM_MESSAGES; ++i) {
        char m[10];
        snprintf(m, sizeof(m), "%zu", i);

        TOX_ERR_GROUP_SEND_MESSAGE err_send;
        tox_group_send_message(toxes[0], group_number, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)m, strlen(m), &err_send);

        // fprintf(stderr, "Send: %zu\n", i);
        ck_assert(err_send == TOX_ERR_GROUP_SEND_MESSAGE_OK);
    }

    fprintf(stderr, "Waiting for packets to be received...\n");

    while (!state[1].lossless_check) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    }

    for (size_t i = 0; i < NUM_GROUP_TOXES; i++) {
        TOX_ERR_GROUP_LEAVE err_exit;
        tox_group_leave(toxes[i], group_number, nullptr, 0, &err_exit);
        ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);
    }

    fprintf(stderr, "All tests passed!\n");
#endif  // VANILLA_NACL
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(NUM_GROUP_TOXES, group_message_test, false);
    return 0;
}

#undef NUM_GROUP_TOXES
#undef PEER1_NICK
#undef PEER1_NICK_LEN
#undef PEER0_NICK
#undef PEER0_NICK_LEN
#undef TEST_GROUP_NAME
#undef TEST_GROUP_NAME_LEN
#undef TEST_MESSAGE
#undef TEST_MESSAGE_LEN
#undef TEST_PRIVATE_MESSAGE_LEN
#undef TEST_CUSTOM_PACKET_LEN
#undef MAX_NUM_MESSAGES
