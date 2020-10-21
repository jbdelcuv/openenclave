// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_BITS_SGX_SEAL_H
#define _OE_BITS_SGX_SEAL_H

#include <openenclave/bits/sgx/sgxtypes.h>

#define OE_SEAL_SGX SGX_FLAGS_INITTED

typedef struct _sgx_sealed_blob_header
{
    sgx_key_request_t key_info;
    uint32_t ciphertext_size; /* also offset of AAD into payload, as cipher
                                 text is followed immediately by AAD */
    uint8_t reserved[12];     /* must be 0 */
    uint32_t payload_size;    /* total size of cipher text and AAD */
    uint8_t iv[12];  /* must be 0 to be compatible with Intel SGX SDK */
    uint8_t tag[16]; /* Authentication Tag */
} oe_sealed_blob_header_t;

#define ki_entropy key_id

#endif /* _OE_BITS_SGX_SEAL_H */
