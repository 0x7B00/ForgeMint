#ifndef FM_KEYBOX_H
#define FM_KEYBOX_H

#include <stdint.h>
#include <stdlib.h>

#define FM_MAX_CERTS 8

struct fm_cert {
    uint8_t *der;
    int der_len;
};

struct fm_key {
    int num_certs;
    struct fm_cert certs[FM_MAX_CERTS];
};

struct fm_ctx {
    int ready;
    struct fm_key key;
};

int fm_keybox_parse(struct fm_ctx *ctx, const uint8_t *data, size_t len);
void fm_keybox_free(struct fm_ctx *ctx);

#endif
