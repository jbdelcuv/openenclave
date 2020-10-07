// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_GCM_H
#define _OE_GCM_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

oe_result_t oe_aes_gcm_encrypt(
    const uint8_t* key,
    size_t keylen,
    const uint8_t* iv,
    size_t ivlen,
    const uint8_t* ad,
    size_t adlen,
    const uint8_t* input,
    size_t inlen,
    uint8_t* output,
    uint8_t* tag);

oe_result_t oe_aes_gcm_decrypt(
    const uint8_t* key,
    size_t keylen,
    const uint8_t* iv,
    size_t ivlen,
    const uint8_t* ad,
    size_t adlen,
    uint8_t* inout,
    size_t iolen,
    const uint8_t* tag);

OE_EXTERNC_END

#endif /* _OE_GCM_H */
