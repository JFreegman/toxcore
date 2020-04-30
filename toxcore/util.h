/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 * Copyright © 2013 plutooo
 */

/*
 * Utilities.
 */
#ifndef C_TOXCORE_TOXCORE_UTIL_H
#define C_TOXCORE_TOXCORE_UTIL_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "logger.h"
#include "crypto_core.h"

#ifdef __cplusplus
extern "C" {
#endif

bool is_power_of_2(uint64_t x);

/* Functions for groupchat extended keys */
const uint8_t *get_enc_key(const uint8_t *key);
const uint8_t *get_sig_pk(const uint8_t *key);
void set_sig_pk(uint8_t *key, const uint8_t *sig_pk);
const uint8_t *get_sig_sk(const uint8_t *key);
void set_sig_sk(uint8_t *key, const uint8_t *sig_sk);
const uint8_t *get_chat_id(const uint8_t *key);


/* id functions */
bool id_equal(const uint8_t *dest, const uint8_t *src);

int id_cmp(const uint8_t *first_id, const uint8_t *second_id);

/* compares two group chat_id's */
bool chat_id_equal(const uint8_t *dest, const uint8_t *src);

uint32_t id_copy(uint8_t *dest, const uint8_t *src); /* return value is CLIENT_ID_SIZE */

// For printing purposes
char *id_toa(const uint8_t *id);

void host_to_net(uint8_t *num, uint16_t numbytes);
void net_to_host(uint8_t *num, uint16_t numbytes);

/* frees all pointers in a uint8_t pointer array, as well as the array itself. */
void free_uint8_t_pointer_array(uint8_t **ary, size_t n_items);

/* Returns -1 if failed or 0 if success */
int create_recursive_mutex(pthread_mutex_t *mutex);

// Safe min/max functions with specific types. This forces the conversion to the
// desired type before the comparison expression, giving the choice of
// conversion to the caller. Use these instead of inline comparisons or MIN/MAX
// macros (effectively inline comparisons).
int16_t max_s16(int16_t a, int16_t b);
int32_t max_s32(int32_t a, int32_t b);
int64_t max_s64(int64_t a, int64_t b);

int16_t min_s16(int16_t a, int16_t b);
int32_t min_s32(int32_t a, int32_t b);
int64_t min_s64(int64_t a, int64_t b);

uint16_t max_u16(uint16_t a, uint16_t b);
uint32_t max_u32(uint32_t a, uint32_t b);
uint64_t max_u64(uint64_t a, uint64_t b);

uint16_t min_u16(uint16_t a, uint16_t b);
uint32_t min_u32(uint32_t a, uint32_t b);
uint64_t min_u64(uint64_t a, uint64_t b);

/* Returns a 32-bit hash of key of size len */
uint32_t jenkins_one_at_a_time_hash(const uint8_t *key, size_t len);

/*
 * Returns true if fuzz factor `f` is greater than a random int <= 100.
 */
bool fuzz_this_byte(unsigned short f);

/*
 * Fills `packet` with random data.
 *
 * @packet The packet to be fuzzed.
 * @length The length of `packet`.
 * @num_extra The number of extra bytes to append to `packet` if there is extra room.
 * @max_size The size of the packet buffer.
 * @start_len The offset of the packet where the fuzzing starts.
 */
uint32_t fuzz_packet(uint8_t *packet, uint32_t length, uint32_t num_extra, size_t max_size, size_t start_len);

#define IDSTRING_LEN (CRYPTO_PUBLIC_KEY_SIZE * 2 + 1)
char *id_to_string(const uint8_t *pk, char *id_str, size_t length);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // C_TOXCORE_TOXCORE_UTIL_H
