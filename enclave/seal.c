// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/crypto/gcm.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>

static const uint8_t _iv[12] = { 0 };

oe_result_t oe_seal(
    const uint8_t* key_info,
    size_t key_info_size,
    const uint8_t* plaintext,
    size_t plaintext_size,
    const uint8_t* additional_data,
    size_t additional_data_size,
    uint8_t **blob,
    size_t *blob_size)
{
    uint8_t* key = NULL;
    size_t key_size = 0;

    oe_sealed_blob_header_t *header;
    uint8_t* payload;
    size_t size;
    oe_result_t result = OE_OK;

    if (key_info == NULL || key_info_size != sizeof(header->key_info) ||
        blob == NULL || blob_size == NULL)
        return OE_INVALID_PARAMETER;

    size = sizeof(*header);
    if (size > OE_UINT32_MAX - plaintext_size)
        return OE_INVALID_PARAMETER;
    size += plaintext_size;
    if (size > OE_UINT32_MAX - additional_data_size)
        return OE_INVALID_PARAMETER;
    size += additional_data_size;

    header = (oe_sealed_blob_header_t*)oe_calloc(1, size);
    if (header == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(oe_get_seal_key(key_info, key_info_size, &key, &key_size));

    payload = (uint8_t*)(header + 1);
    OE_CHECK(oe_aes_gcm_encrypt(key, key_size, _iv, sizeof(_iv),
                                additional_data, additional_data_size,
                                plaintext, plaintext_size,
                                payload, header->tag));

    OE_CHECK(oe_memcpy_s(&header->key_info, sizeof(header->key_info),
                         key_info, key_info_size));

    OE_CHECK(oe_memcpy_s(payload + plaintext_size, additional_data_size,
                         additional_data, additional_data_size));

    header->aad_offset = (uint32_t)plaintext_size;
    header->payload_size = (uint32_t)(plaintext_size + additional_data_size);

    *blob = (uint8_t*)header;
    *blob_size = size;

done:
    oe_free_seal_key(key, NULL);
    if (result != OE_OK)
        oe_free(header);
    return result;
}

oe_result_t oe_unseal(
    uint8_t* blob,
    size_t blob_size,
    uint8_t** plaintext,
    size_t* plaintext_size,
    uint8_t** additional_data,
    size_t* additional_data_size)
{
    oe_sealed_blob_header_t *header;
    uint8_t* payload;
    uint8_t* key;
    size_t key_size;
    oe_result_t result = OE_OK;

    if (blob == NULL || blob_size < sizeof(*header))
        return OE_INVALID_PARAMETER;

    header = (oe_sealed_blob_header_t*)blob;
    payload = (uint8_t*)(header + 1);
    if (header->payload_size != blob_size - sizeof(*header))
        return OE_UNEXPECTED;

    OE_CHECK(oe_get_seal_key((uint8_t*)&header->key_info,
                             sizeof(header->key_info), &key, &key_size));

    OE_CHECK(oe_aes_gcm_decrypt(key, key_size, _iv, sizeof(_iv),
                                payload + header->aad_offset,
                                header->payload_size - header->aad_offset,
                                payload, header->aad_offset, header->tag));

    if (plaintext)
        *plaintext = payload;
    if (plaintext_size)
        *plaintext_size = header->aad_offset;
    if (additional_data)
        *additional_data = payload + header->aad_offset;
    if (additional_data_size)
        *additional_data_size = header->payload_size - header->aad_offset;

done:
    if (key)
        oe_free_seal_key(key, NULL);
    return result;
}
