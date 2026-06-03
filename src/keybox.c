#include "keybox.h"
#include "log.h"
#include <string.h>

int fm_keybox_parse(struct fm_ctx *ctx, const uint8_t *data, size_t len)
{
    memset(ctx, 0, sizeof(*ctx));
    if (!data || len < 4) return -1;

    uint32_t count = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
                   | ((uint32_t)data[2] << 8)  | (uint32_t)data[3];

    ctx->key.num_certs = 0;
    size_t pos = 4;
    for (uint32_t i = 0; i < count && i < FM_MAX_CERTS && pos + 4 <= len; i++) {
        uint32_t cert_len = ((uint32_t)data[pos] << 24) | ((uint32_t)data[pos + 1] << 16)
                          | ((uint32_t)data[pos + 2] << 8)  | (uint32_t)data[pos + 3];
        pos += 4;
        if (pos + cert_len > len) break;

        struct fm_cert *fc = &ctx->key.certs[ctx->key.num_certs++];
        fc->der = malloc(cert_len);
        if (fc->der) {
            memcpy(fc->der, data + pos, cert_len);
            fc->der_len = cert_len;
        }
        pos += cert_len;
    }

    ctx->ready = ctx->key.num_certs > 0 ? 1 : 0;
    LOG("parsed %d certs", ctx->key.num_certs);
    return ctx->ready ? 0 : -1;
}

void fm_keybox_free(struct fm_ctx *ctx)
{
    for (int i = 0; i < ctx->key.num_certs; i++)
        free(ctx->key.certs[i].der);
    memset(ctx, 0, sizeof(*ctx));
}
