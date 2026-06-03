#include "keybox.h"
#include "hook.h"
#include "log.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

__attribute__((visibility("default"))) bool fm_entry(void *handle,
                                                      void *certs_data,
                                                      uint32_t certs_size)
{
    (void)handle;
    static struct fm_ctx ctx;

    if (certs_data && certs_size > 0)
        fm_keybox_parse(&ctx, (const uint8_t *)certs_data, certs_size);
    else
        LOG("no certs data");

    if (fm_hook_init(&ctx) < 0) {
        LOG("hook init failed");
        return false;
    }

    LOG("hooks installed");
    return true;
}
