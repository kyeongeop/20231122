#ifndef KR_PARSER_H
#define KR_PARSER_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define KR_MAGIC1 "KRFIXH01"
#define KR_MAGIC2 "KRFIXP02"
#define KR_MAGIC3 "KRFIXA03"

#define KR_HDR_LEN 16
#define KR_PLD_LEN 48
#define KR_ATT_LEN 44
#define KR_TOTAL_LEN (KR_HDR_LEN + KR_PLD_LEN + KR_ATT_LEN)

typedef struct {
  const uint8_t *base;
  size_t off1, off2, off3;
  uint32_t key_id;
  uint32_t server_epoch;
  uint32_t client_epoch;
  uint32_t attest_epoch;
} kr_frame_t;

static uint32_t kr_read_u32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static const uint8_t *kr_find(const uint8_t *data, size_t size,
                              const char *magic, size_t *out_off) {
  size_t mlen = 8;
  if (size < mlen) return NULL;
  for (size_t i = 0; i + mlen <= size; i++) {
    if (memcmp(data + i, magic, mlen) == 0) {
      *out_off = i;
      return data + i;
    }
  }
  return NULL;
}

/* Returns 0 on success, non-zero on malformed input. */
static int kr_parse(const uint8_t *data, size_t size, kr_frame_t *f) {
  memset(f, 0, sizeof(*f));
  f->base = data;
  const uint8_t *p1 = kr_find(data, size, KR_MAGIC1, &f->off1);
  if (!p1 || f->off1 + KR_HDR_LEN > size) return 1;
  const uint8_t *p2 = kr_find(data, size, KR_MAGIC2, &f->off2);
  if (!p2 || f->off2 + KR_PLD_LEN > size || f->off2 <= f->off1) return 2;
  const uint8_t *p3 = kr_find(data, size, KR_MAGIC3, &f->off3);
  if (!p3 || f->off3 + KR_ATT_LEN > size || f->off3 <= f->off2) return 3;
  f->key_id = kr_read_u32(p1 + 8);
  f->server_epoch = kr_read_u32(p1 + 12);
  f->client_epoch = kr_read_u32(p2 + 8);
  f->attest_epoch = kr_read_u32(p3 + 8);
  return 0;
}

/*
 * Evaluate the key-rotation record. The correct policy rejects frames whose
 * sealing key does not match the attestation record:
 *
 *   server_epoch == attest_epoch  -> rotation was committed
 *   client_epoch == attest_epoch  -> frame was sealed under the current key
 *
 * Returns:
 *    0  accepted frame
 *   77  key-rotation failure reproduced (stale key trusted by vuln build)
 *   78  stale frame correctly rejected (fixed build only)
 *    1  malformed input
 */
static int kr_evaluate(const kr_frame_t *f) {
  int stale = (f->client_epoch != f->attest_epoch) ||
              (f->server_epoch != f->attest_epoch);
#ifdef KR_FIXED
  /* Localized correction: the vulnerable build skips this epoch check and
   * trusts any frame carrying a valid-looking header, so a key sealed under
   * the previous epoch (client_epoch < attest_epoch) is replayed. */
  if (stale) return 78;
#else
  /* BUG "key rotation failure": the parser never compares the sealing key
   * epoch against the attestation record. A stale frame is therefore trusted
   * and the missing rotation is silently accepted. We keep the comparison
   * result so the verdict is explicit, but take no corrective action - this
   * is the exact branch KR_FIXED restores. */
  if (stale) return 77;
#endif
  return 0;
}

#endif
