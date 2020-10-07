// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_BITS_SGX_SEAL_H
#define _OE_BITS_SGX_SEAL_H

#include <openenclave/bits/sgx/sgxtypes.h>

#define OE_SEAL_SGX_SPECIFIC    1ULL

typedef struct _oe_sealed_blob_header
{
    sgx_key_request_t   key_info;
    uint32_t            aad_offset;
    uint8_t             reserved1[12];
    uint32_t            payload_size;   /* total size of ciphertext and AAD */
    uint8_t             reserved2[12];
    uint8_t             tag[16];
} oe_sealed_blob_header_t;

#endif /* _OE_BITS_SGX_SEAL_H */
