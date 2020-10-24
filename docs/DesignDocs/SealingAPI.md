# Open Enclave Sealing API

This document describes API functions provided by the Open Enclave SDK for
sealing/unsealing data against an enclave's identity.

## Motivation

Sealing is an important capability of TEEs, which allows an enclave to encrypt
and/or integrity-protect data at rest, using keys (aka., sealing keys) derived
from the enclave's own identity. TEEs may have distinct formulas for key
derivation, and may support different key lengths. And that leads to the desire
for a TEE-agnostic sealing API.

### Objectives

The sealing API should be:

- *TEE-agnostic* - The API should hide TEE specifics to allow reuse of source
  code across TEEs.
- *Accommodative* - Should the developers choose to, the API should allow
  explicit uses of TEE specific features. For example, in the case of SGX, the
  API should allow deriving keys of type `PROVISION_SEAL_KEY`, which may not
  have an equivalent on other TEEs.
- *Easy to use* - It's always a challenge for average developers to encrypt
  data securely by using seal keys directly. The API should shield
  cryptographic complexities from developers, by offering comprehensive
  protection through an intuitive interface.
- *Interoperable with existing SDKs* - The Intel SGX SDK also provides sealing
  capabilities. It's desirable for enclaves, regardless of the SDKs they built
  with, to be able to exchange sealed blobs, when allowed by the policy.

### Non-Objectives

- Cross-device sealing/unsealing is **not** supported - Sealed blobs created on a device must be unsealed on that same device.
- Cross-TEE sealing/unsealing is **not** supported - Sealed blobs created by an
  enclave in one TEE (e.g., SGX) cannot be unsealed by another enclave in a
  different TEE (e.g., OP-TEE), even if they were both signed by the same
  private key.

## User Experience

At the minimum, two API functions are necessary, namely `oe_seal()` and
`oe_unseal()`. The former encrypts user data into a blob (whose format is
implementation specific) while the latter decrypts/verifies the given blob and
returns the data back to the user.

`oe_seal()` requires a seal key to do its job. But how can a seal key be passed to
`oe_seal()`? Here are 3 options:

1. `oe_seal()` takes the seal key directly as a function argument; or
2. `oe_seal()` takes a `key_info` as its argument for deriving the desired seal
   key; or
3. `oe_seal()` takes a `seal_policy` as its argument, and calls
   `oe_get_seal_key_by_policy()` to obtain the seal key.

Option 1 implies access to the seal key by software, which isn't always true
(e.g., TPM never reveals seal keys to software). Option 3 prohibits developers
from fine-tuning `key_info` (probably in a TEE-specific manner), which violates
the *Accommodative* requirement. Option 2 is our choice.

Now that `key_info` has been passed to `oe_seal()` and it has to be persisted
for `oe_unseal()`, it's a natural idea to embed `key_info` into the sealed
blob. Combined with the considerations above we come to the declarations of
`oe_seal()` and `oe_unseal()` that are shown below. Meanings of the function
parameters should be intuitive. More details can be found in
[oe_seal()](#oe_seal()) and [oe_unseal()](#oe_unseal()) later in this document.

```C
oe_result_t oe_seal(
    const uint8_t* key_info,
    size_t key_info_size,
    const uint8_t* plaintext,
    size_t plaintext_size,
    const uint8_t* additional_data,
    size_t additional_data_size,
    uint8_t **blob,
    size_t *blob_size);

oe_result_t oe_unseal(
    uint8_t* blob,
    size_t blob_size,
    uint8_t** plaintext,
    size_t* plaintext_size,
    uint8_t** additional_data,
    size_t* additional_data_size);
```

The code snippet below shows how to encrypt data (i.e., `my_data_size` bytes
starting at `my_data`) using `oe_seal()`.

```C
uint8_t* blob;
size_t blob_size;
result = oe_seal(key_info,
                 key_info_size,
                 my_data,       // plaintext
                 my_data_size,  // plaintext_size
                 NULL,          // additional_data
                 0,             // additional_data_size
                 &blob,
                 &blob_size);
id (result != OE_OK)
    // Handle encryption error...
else
{
    // Persist blob...

    oe_free(blob); // Free blob when done
}
```

Please note that `my_data` above will be both encrypted and
integrity-protected. But if only integrity needs protection, one could instead
pass `my_data` and `my_data_size` as `additional_data` and
`additional_data_size`, respectively.

```C
uint8_t* blob;
size_t blob_size;
result = oe_seal(key_info,
                 key_info_size,
                 NULL,          // plaintext
                 0,             // plaintext_size
                 my_data,       // additional_data
                 my_data_size,  // additional_data_size
                 &blob,
                 &blob_size);
id (result != OE_OK)
    // Handle encryption error...
else
{
    // Persist blob...

    oe_free(blob); // Free blob when done
}
```

Please note that the blob format is proprietary so there's no architectural way
to extract `additional_data` or `additional_data_size` without unsealing the
blob. That said, the only way to recover `my_data` (and `my_data_size`) is
still via `oe_unseal()`, regardless of whether it was encrypted or not. In other words,
the two code snippets above are identical from a functional perspective but
differ in security. Therefore, developers are strongly encouraged to use
encryption for comprehensive protection.

`oe_unseal()` decrypts a sealed blob **in-place**. The code snippet below shows
how to decrypt a sealed blob and retrieve a pointer to the plaintext. Please
note that `my_data` after this call will point to somewhere within `blob`.

```C
result = oe_unseal(blob,
                   blob_size,
                   &my_data,        // plaintext
                   &my_data_size,   // plaintext_size
                   NULL,            // additional_data
                   NULL);           // additional_data_size
if (result != OE_OK)
    // Handle decryption error...
else
{
    // Process my_data...
}
```

The initial `key_info` passed to `oe_seal()` could be retrieved by a call to
`oe_get_seal_key_by_policy()`, which takes a `seal_policy` as its only input
parameter. In practice, an enclave may desire to encrypt different things under
different keys. Per
[NIST.SP800-108](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf),
*Label* and *Context* should be among the inputs to *KDF* (*Key Derivation
Function*). Most TEEs also support taking addtional *context* or *entropy* into
key derivation. The existing `oe_get_seal_key_by_policy()` API however lacks
that support and prompts for a new API to fill the gap.

The new `oe_get_seal_key_info()` API is introduced with the following
signature.

```C
oe_result_t oe_get_seal_key_info(
    oe_seal_policy_t seal_policy,
    uint8_t* entropy,
    size_t entropy_size,
    uint64_t tee_specific,
    uint8_t** key_info,
    size_t* key_info_size);
```

If compared to `oe_get_seal_key_by_policy()`, `oe_get_seal_key_info()` differs
in:

- The addition of `entropy`/`entropy_size` parameters - This allows *Label* or
  *Context* (or both), or simply more entropy to be mixed into the seal key.
- The addition of `tee_specific` parameter - This is a TEE specific parameter,
  or `OE_SEAL_TEE_AGNOSTIC` to use TEE defaults. See
  [oe_get_seal_key_info()](#oe_get_seal_key_info()) later in this document for
  more information.
- The removal of `key_buffer`/`key_size` output parameters - Direct uses of seal
  keys are error prone so discouraged.

The code snippet below shows how to create a `key_info` suitable for a
provisioning enclave. It adds `PROVISION_KEY` to the attribute mask, and uses
`PROVISION_SEAL_KEY` to exclude CPU SVN from key derivation.

```C
sgx_key_request_t *key_info;
size_t key_info_size;
result = oe_get_seal_key_info(OE_SEAL_POLICY_PRODUCT, NULL, 0,
                              OE_SEAL_SGX | OE_SEALKEY_DEFAULT_FLAGSMASK |
                              SGX_FLAGS_PROVISION_KEY,
                              (uint8_t**)&key_info, &key_info_size);
if (result != OE_OK)
    // Handle errors...
else
    key_info->key_name = SGX_KEYSELECT_PROVISION_SEAL;
```

## Specification

New files:

- [include/openenclave/bits/seal.h](../../include/openenclave/bits/seal.h)
  contains generic definitions.
- [include/openenclave/bits/sgx/seal.h](../../include/openenclave/bits/sgx/seal.h)
  contains SGX specific definitions.
- [enclave/seal_gcm-aes.c](../../enclave/seal_gcm-aes.c) implements `oe_seal()`
  and `oe_unseal()`.
- [enclave/crypto/gcm.c](../../enclave/crypto/gcm.c) implements *GCM-AES128*.

Modified files:

- [include/openenclave/enclave.h](../../include/openenclave/enclave.h)
  declares `oe_get_seal_key_info()`, `oe_seal()` and `oe_unseal()`.
- [enclave/core/sgx/keys.c](../../enclave/core/sgx/keys.c) implements
  `oe_get_seal_key_info()`.

### oe_seal()

```C
/**
 * Seal data to an enclave using AEAD (Authenticated Encryption with Additional
 * Data).
 *
 * @param[in] key_info The enclave-specific key information to derive the seal
 * key with.
 * @param[in] key_info_size The size of the \p key_info buffer.
 * @param[in] plaintext Optional buffer to be encrypted under the seal key.
 * @param[in] plaintext_size Size of \p plaintext, must be \c 0 if \p plaintext
 * is \c NULL.
 * @param[in] additional_data Optional additional data to be included in the
 * final MAC.
 * @param[in] additional_data_size Size of \p additional_data, must be \c 0 if
 * \p additional_data is \c NULL.
 * @param[out] blob On success, receive the pointer to a buffer containing both
 * \p additional_data and encrypted \p plaintext, along with necessary
 * information for unsealing. Freed by oe_free().
 * @param[out] blob_size On success, receive the size of \p blob.
 *
 * @retval OE_OK \p plaintext and \p additional_data were sealed to the enclave
 * successfully.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 * @retval OE_CRYPTO_ERROR Error occurred during encryption.
 */
oe_result_t oe_seal(
    const uint8_t* key_info,
    size_t key_info_size,
    const uint8_t* plaintext,
    size_t plaintext_size,
    const uint8_t* additional_data,
    size_t additional_data_size,
    uint8_t **blob,
    size_t *blob_size);
```

`oe_seal()` encrypts and packages user data into a sealed blob using *AEAD*
(*Authenticated Encryption with Additional Data*). A sealed blob is comprised
of a header, followed immediately by payload, which is the concatenation of
cipher text and *AAD* (*Additional Authenticated Data*).

The blob header is TEE specific. On SGX, for interoperability, we adopted the
same format as the Intel SGX SDK. Below gives the definition of
`oe_sealed_blob_header_t` on SGX.

```C
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
```

Even though `oe_sealed_blob_header_t` is TEE specific, the source code of
`oe_seal()` (and `oe_unseal()` described later) can still be generic, as long
as `oe_sealed_blob_header_t` has the following fields.

- `key_info` - This holds `key_info` to be used by `oe_unseal()` to retrieve
  the same seal key. Its size must match `key_info_size` argument passed in.
- `key_info.ki_entropy` - This holds extra entropy to be mixed into the seal
  key. `ki_entropy` is a macro that expands to `key_id` on SGX, as shown above.
- `iv` - This is the *IV* (*Initial Vector*) used by the underlying cipher.
- `tag` - *AT* (*Authentication Tag*). It must be big enough to accommodate
  *AT*, whose size varies depending on the underlying cipher.
- `payload_size` - Size of the payload that follows the header immediately.
- `ciphertext_size` - Size of the cipher text, or the offset into the payload
   where *AAD* starts (as *AAD* follows the cipher text immediately).

Below shows a possible `oe_seal()` implementation. Please note that *GCM* is
chosen here. Other cipher modes, such as *CCM* and *OCB*, would also work. *GCM* wins
the election because

- It is faster than *CCM*.
- It is patent free when compared to *OCB*.
- It is the cipher mode chosen by the Intel SGX SDK, so is required for
  interoperability.

```C
oe_result_t oe_seal(
    const uint8_t* key_info,
    size_t key_info_size,
    const uint8_t* plaintext,
    size_t plaintext_size,
    const uint8_t* additional_data,
    size_t additional_data_size,
    uint8_t** blob,
    size_t* blob_size)
{
    uint8_t* key = NULL;
    size_t key_size = 0;

    oe_sealed_blob_header_t* header;
    oe_entropy_kind_t k;
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

    oe_secure_zero_fill(header, sizeof(*header));

    OE_CHECK(oe_memcpy_s(
        &header->key_info, sizeof(header->key_info), key_info, key_info_size));

    OE_CHECK(oe_get_entropy(
        header->key_info.ki_entropy, sizeof(header->key_info.ki_entropy), &k));

    OE_CHECK(oe_get_seal_key(
        (uint8_t*)&header->key_info, key_info_size, &key, &key_size));

    payload = (uint8_t*)(header + 1);
    OE_STATIC_ASSERT(sizeof(header->tag) >= 16);
    OE_CHECK(oe_aes_gcm_encrypt(
        key,
        key_size,
        header->iv,
        sizeof(header->iv),
        additional_data,
        additional_data_size,
        plaintext,
        plaintext_size,
        payload,
        header->tag));

    OE_CHECK(oe_memcpy_s(
        payload + plaintext_size,
        additional_data_size,
        additional_data,
        additional_data_size));

    header->ciphertext_size = (uint32_t)plaintext_size;
    header->payload_size = (uint32_t)(plaintext_size + additional_data_size);

    *blob = (uint8_t*)header;
    *blob_size = size;

done:
    oe_free_seal_key(key, NULL);
    if (result != OE_OK)
        oe_free(header);
    return result;
}
```

The above implementation generates `key_info.ki_entropy` randomly and uses a
constant *IV* of 0<sup>96</sup> on every invocation. The rationale behind that
is that, per
[NIST.SP800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf),
an encryption key shall not be used in more than 2<sup>32</sup> invocations.
But there's no way for `oe_seal()` to track how many times it has been invoked
with the same key. Thus, it uses a fresh key on every invocation. Now that the
key is fresh, it's safe to use a constant *IV*. 0<sup>96</sup> is chosen for
interoperability with the Intel SGX SDK.

### oe_unseal()

```C
/**
 * Unseal in place a blob sealed by oe_seal().
 *
 * @param[in,out] blob The blob to be unsealed in place.
 * @param[in] blob_size Size of \p blob.
 * @param[out] plaintext On success, receive the pointer to the decrypted data
 * within \p blob. This parameter is optional.
 * @param[out] plaintext_size On success, receive the size of \p plaintext.
 * This parameter is optional.
 * @param[out] additional_data On success, receive the pointer to the
 * additional authenticated data within \p blob. This parameter is optional.
 * @param[out] additional_data_size On success, receive the size of
 * \p additional_data. This parameter is optional.
 *
 * @retval OE_OK Unsealed \p blob successfully.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 * @retval OE_CRYPTO_ERROR Error occurred during decryption.
 */
oe_result_t oe_unseal(
    uint8_t* blob,
    size_t blob_size,
    uint8_t** plaintext,
    size_t* plaintext_size,
    uint8_t** additional_data,
    size_t* additional_data_size);
```

`oe_unseal()` decrypts and verifies the integrity of a sealed blob created by `oe_seal()`. The decryption is done **in-place**. On success, `plaintext`/`additional_data`, if not `NULL`, receives the pointer into the decrypted blob where the plaintext/*AAD* is. Similarly, `plaintext_size`/`additional_data_size` receives the sizes on success if not `NULL`.

Below shows a possible `oe_unseal` implementation that matches the `oe_seal()` implementation above.

```C
oe_result_t oe_unseal(
    uint8_t* blob,
    size_t blob_size,
    uint8_t** plaintext,
    size_t* plaintext_size,
    uint8_t** additional_data,
    size_t* additional_data_size)
{
    oe_sealed_blob_header_t* header;
    uint8_t* payload;
    uint8_t* key = NULL;
    size_t key_size = 0;
    oe_result_t result = OE_OK;

    if (blob == NULL || blob_size < sizeof(*header))
        return OE_INVALID_PARAMETER;

    header = (oe_sealed_blob_header_t*)blob;
    payload = (uint8_t*)(header + 1);
    if (header->payload_size != blob_size - sizeof(*header) ||
        header->payload_size < header->ciphertext_size)
        return OE_UNEXPECTED;

    OE_CHECK(oe_get_seal_key(
        (uint8_t*)&header->key_info,
        sizeof(header->key_info),
        &key,
        &key_size));

    OE_CHECK(oe_aes_gcm_decrypt(
        key,
        key_size,
        header->iv,
        sizeof(header->iv),
        payload + header->ciphertext_size,
        header->payload_size - header->ciphertext_size,
        payload,
        header->ciphertext_size,
        header->tag));

    if (plaintext)
        *plaintext = payload;
    if (plaintext_size)
        *plaintext_size = header->ciphertext_size;
    if (additional_data)
        *additional_data = payload + header->ciphertext_size;
    if (additional_data_size)
        *additional_data_size = header->payload_size - header->ciphertext_size;

done:
    oe_free_seal_key(key, NULL);
    return result;
}
```

### oe_get_seal_key_info()

```C
/**
 * Get enclave-specific key information that could be passed to
 * oe_get_seal_key_v2() to derive a symmetric encryption key coupled to the
 * enclave platform.
 *
 * @param[in] seal_policy The policy for the identity properties used to derive
 * the seal key.
 * @param[in] entropy Optional parameter containing additional entropy for key
 * derivation. If \c NULL, oe_get_seal_key_info() will generate entropy on
 * behalf of the caller.
 * @param[in] entropy_size Must be \c 0 if \p entropy is \c NULL.
 * @param[in] tee_specifc \c OE_SEAL_TEE_AGNOSTIC to use TEE defaults. If \c
 * OE_SEAL_SGX is specified, the rest of \p tee_specifc is interpreted as the
 * \a attribute_mask for \c EGETKEY on SGX.
 * @param[out] key_info On success this points to the enclave-specific key
 * information which can be used to retrieve the key by passing it to
 * oe_get_seal_key_v2(). Freed by calling oe_free_seal_key() or oe_free_key().
 * @param[out] key_info_size On success, this is the size of the \p key_info
 * buffer.
 *
 * @retval OE_OK The seal key info was successfully requested.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 */
oe_result_t oe_get_seal_key_info(
    oe_seal_policy_t seal_policy,
    uint8_t* entropy,
    size_t entropy_size,
    uint64_t tee_specifc,
    uint8_t** key_info,
    size_t* key_info_size);
```

`oe_get_seal_key_info()` duplicates largely the logic of
`oe_get_seal_key_by_policy()`. Please see [User Experience](#user-experience)
earlier in this documentation for an explanation on the intention of this
API.

`seal_policy` selects the type of enclave identity and has the same definition
and supported values as in `oe_get_seal_key_by_policy()`.

`entropy`/`entropy_size` supplies additional data as input to the KDF.
Different TEEs may expect different entropy sizes, e.g., SGX expects 256-bit
entropy. If `entropy_size` isn't the same as expected, `entropy` will be hashed
before being passed on to the underlying TEE. `entropy` could be `NULL` and if
that's the case, `entropy_size` must be `0`, and a random bit sequence of
expected size will be used instead.

`tee_specific` is a 64-bit TEE specific parameter. Its interpretation varies
from TEE to TEE. It could be an integer on one TEE, or a pointer to some
structure on another. Its purpose is to pass additional parameters that need to
be tuned frequently, e.g., `attribute_mask` on SGX. It doesn't intend to be
comprehensive, as fine tunes can always be done by casting `key_info` into the
TEE specific structure (e.g., `sgx_key_request_t` on SGX) and modifying it
there.

Values of `tee_specific` currently defined are listed in the table below.

|Value|TEE|Definition|
|-----|---|----------|
|`OE_SEAL_TEE_AGNOSTIC`|*All*|No TEE specific features are requested. Signify to use TEE defaults.
|`OE_SEAL_SGX \| <attribute_mask>`|**SGX**|`<attribute_mask>` specifies `sgx_key_request_t::attribute_mask` as input to `EGETKEY`.

`OE_SEAL_TEE_AGNOSTIC` is TEE neutral. Defining it to zero should suffice.

```C
#define OE_SEAL_TEE_AGNOSTIC 0
```

`OE_SEAL_SGX` should be defined **if and only if** SGX is the target TEE, in
order to guarantee a compiler error should the code be compiled targeting a
different TEE. The value `SGX_FLAGS_INITED` is recommended as it can never be
part of an attribute mask.

```C
#if __x86_64__ || _M_X64
#include <openenclave/bits/sgx/sgxtypes.h>
#define OE_SEAL_SGX SGX_FLAGS_INITTED
#endif
```

Each TEE supporting this API should define the macro `OE_SEAL_<TEE>`.
Referencing to `OE_SEAL_<TEE>` would make the caller source code TEE aware -
i.e., the caller source code could be compiled on the selected TEE only, or a
compiler error would result.

## Alternatives (Opens)

### How to support crypto-agility?

According to [wikipedia](https://en.wikipedia.org/wiki/Crypto-agility),

> Crypto-agility (cryptographic agility) is a practice paradigm in designing information security systems that encourages support of rapid adaptations of new cryptographic primitives and algorithms without making significant changes to the system's infrastructure.

The proposed `oe_seal()` doesn't offer choices of crypto suites to developers. To see why, please consider the following:

- Key Length - A TEE usually has its preferred key length tied to its hardware. E.g., SGX uses 128-bit fuse keys to derive seal keys, hence 128-bit is the preferred key length.
  - Longer keys don't add security, as the adversary would then attack the fuse key instead. After all, only the weakest link matters in security.
  - Shorter keys lower security without significant benefits (except probably slight improvement in performance).
- Cipher - A TEE may have preferred ciphers. E.g., AES is preferred on SGX (or x86_64 processors generally) because of *AES-NI*.
  - Other ciphers without native support are slower and probably more vulnerable to side-channel attacks.
- Mode and/or Algorithm for Integrity Protection - Similar to ciphers, a TEE may have preferred hash algorithms or cipher modes. E.g., SGX (or x86_64 processors generally) offers the `PCLMULQDQ` instruction for expediting GHASH, and *SHA-NI* for SHA-1 and SHA-256 calculations.

Based on the above analyses, it is better to let `oe_seal()` pick the encryption algorithm than to let the developer specify one.

Then there rises the question: **What if a new algorithm needs to be used?**

A new/different algorithm could be needed/desired due to:

1. Personal perference
2. Vulnerabilities or weaknesses
3. Government regulation

For `oe_seal()`,

- (1) is not a concern generally. Please note that sealing/unsealing must be done in the same TEE on the same device, by enclaves developed by the same ISV. There's no reason for those enclaves to choose different ciphers.
- (2) is a rare event. It usually takes 10+ years for an algorithm to undergo vigorous cryptanalyses before it prevails. Once it did that, it usually takes longer to develop practical exploits (just recall how long it took to migrate from DES to AES). Therefore, rather than offering choices at the API today, it makes more sense to change the implementation when the time comes.
- (3) is the most practical problem. Different implementations of `oe_seal()`/`oe_unseal()` could be packaged into different libraries. It's the ISV's responsibility to pick the right version at build time, depending on what country the enclave is being shipped to.
  - [ ] (**Decision?**) Package sealing implementation in its own lib (`liboeseal_gcm_aes`)?

For `oe_unseal()`, the algorithm was determined by `oe_seal()` and `oe_unseal()` just needs to match it. Neither (1) nor (3) is a concern.

- (1) should not happen simply.
- (3) requires both the sealer and the unsealer to link with the same sealing implementation, which is the ISV's responsibility. A mismatch would fail the unsealer but would **not** compromise security.
- (2) requires support from the sealed blob format and `oe_unseal()`. A simple solution could be to introduce a `revision` field in the blob header when the time comes.
  - [ ] (**Decision?**) Reserve `revision` today? What size?
    - [ ] 8-bit
    - [ ] 16-bit
    - [ ] 32-bit

### How to enable TEE-specific features?

Different TEEs support different features for seal key derivation. E.g., SGX's `KEYREQUEST` contains fields that may not have equivalents on other TEEs, such as `KEYNAME`, `ATTRIBUTEMASK`, `CETMASK`, `MISCMASK`, etc.

(**Decission?**) What to expose at API level?

- [X] Simple API to take "common" parameters and allow fine-tunes in a TEE-specific manner.
  - [X] `entropy` buffer to take in *Label*/*Context* for *KDF*.
  - [ ] `tee_specific` - Not reommended, current proposal.
  - The rest of `key_info` takes TEE defaults and can be fine-tuned in a TEE specific manner.
- [ ] Comprehensive API to take "all" parameters.
  - [ ] List all parameters as function arguments - Not recommended, as the API would no longer be TEE agnostic.
  - [ ] Pass parameters in a structure - Not recommended because it's hard to specify which fields are specified and which are not (i.e. TEE default should be used).

### Static libs vs. plug-ins

From Simon Leet on Oct 26, 2020:

> As I look over the iterations of the PR, I think fundamental design issue around the adding Sealing to OE SDK remains unaddressed for me. Thinking of ways to rephrase this, I think there's a conflict of several requirements not characterized in the objective for the design:
>
> 1. Provide a sealing API that is compatible with Intel SGX SDK existing sealing API.
> 2. Provide a user-friendly sealing API that is TEE-agnostic.
> 3. Do not change existing OE sealing key APIs.
>
> (3) is, of course, not actually stated as an objective in this design, but it's clearly something that's adhered to when looking at the proposed design. I think that needs to be actively called out as a non-goal, and that part of this design needs to consider what the fate of those APIs should be, especially because implicit in the stated _Easy to use_ objective, the implication is that those existing APIs do not meet that criterion.
>
> Instead of trying to tweak this design towards acceptability, I'll propose an entirely different strawman design that I want folks to think about that we can then compare and debate:
>
> * OE SDK no longer provides `oe_get_seal_key` to an end user.
> * OE SDK implements a plug-in model for sealing functionality, much in the same way that it has for attestation.
>
>   * A TEE provider (like SGX) is responsible for implementing a plug-in that knows how seal/unseal on that TEE platform and _defines a plug-in-specific cryptosuite and data blob format._
>
>     * This shifts the crypto-agility problem out of the SDK; a developer can adopt alternative implementations of sealing plugins or plugins using different (newer) cryptosuites without relying on the SDK to determine that on their behalf.
>   * OE SDK provides `oe_seal` and `oe_unseal` APIs that are wrappers over TEE plug-in implementation.
>
>     * Many of the ideas from attestation plug-ins may carry over here, such as UUID targeting, plug-in registration, etc. Some will get simplified (e.g. UUID is always embedded in sealed blob because there is no cross-TEE sealing)
>     * Some or all of the OE semantics may go away attempting to generalize sealing policies across TEEs, much in the same way that attestation plugins don't attempt to build on top of the old `oe_parse_report` semantics.
>     * For example, consider a trivial use case where the user has no control over sealing parameters at all if they write cross-TEE code; `oe_seal` just calls the appropriate TEE-plugin and it seals with a default policy of its choice (e.g. always with MRENCLAVE for SGX). The TEE-plugin may then expose its custom set of properties through an opaque blob type through the `oe_seal` API that a user that wants to customize functionality on a specific TEE can manipulate themselves (e.g. `sgx_key_request` struct for SGX).
>
> I'm not proposing that we actually run off and go build this strawman (there are some other problems I'm glossing over here like the `oe_get_private_key` API) but it represents a high level concept for an alternative that I think hits some of the stated objectives better:
>
> * Actually TEE-agnostic, bakes less implementation directly into OE SDK (or at least, could be more easily broken out as standalone components moving forwards)
> * Accommodative in that the plug-ins get to expose the full range of options specific to a TEE if desired without it filtering through an OE SDK aggregation layer.
>
>   * The trade-off being less expressive sealing semantics for apps that want to span different TEEs, at least in this strawman version.
> * Easy to use in that there's no management of key info at all, and that's incorporated into the `oe_seal` function.
>
>   * With proper built-in defaults per TEE, it could also avoid some of the registration complexity associated with attestation plugins, again because there's a much stronger binding of TEE the enclave is running in vs. attestation.
> * Interoperable with existing Intel SDK, since Intel controls the plugin entirely, they can choose to provide that functionality as they see fit.

Plug-ins allows multiple implementations to coexist and allows the developer to choose which plug-ins to go into the enclave. Based on the analyses in previous sections, plug-ins are not necessary IMHO.

- [ ] (**Decision?**) Plug-in model

### How to specify seal keys?

There are 3 options to specify seal key for `oe_seal()`.

- [ ] `oe_seal()` takes all necessary parameters for deriving `key_info` and the seal key.
  - This gives users a one-stop experience.
  - But it won't work for (TEE specific) features not exposed as a parameter.
- [X] `oe_seal()` takes `key_info` for deriving the seal key.
- [ ] `oe_seal()` takes the seal key directly.
  - This won't work for TEEs that don't expose seal keys.
  - `key_info` is still needed to be persisted (as part of the output blob). That said, this option is inferior to the previous one.

### How to obtain `key_info`?

There is an existing API `oe_get_seal_key_by_policy()` that returns both a `key_buffer` and the corresponding `key_info`. It's however considered insufficient in most cases due to the lack of *Label*/*Context* support as inputs to *KDF*s per NIST.SP800-108.

(**Decision?**) There are 2 options to add *Label*/*Context* support.

- [ ] Extend `oe_get_seal_key_by_policy_v3()` with additional parameters.
  - API name may be confusing - With the added parameters, it's no long `by_policy` only.
  - Direct use of seal keys should be discouraged.
- [X] Define new `oe_get_seal_key_info()` with all needed parameters.
  - Return `key_info` only.
- The current `oe_get_seal_key_by_policy_v2()` will be deprecated either way.

### Shall *AAD* (*Additional Authenticated Data*) be supported?

(**Decision?**) The Intel SGX SDK's sealing API supports *AAD*. In the case of the Open Enclave SDK, the blob format is proprietary, thus *AAD* cannot be retrieved from a sealed blob without unsealing. That said, it doesn't make a difference functionally whether *AAD* is encrypted or not.

- [X] Support *AAD* - to stay interoperable with the Intel SGX SDK.
- [ ] Do **not** support *AAD* - to discourage the use of *AAD* in sealing.
  - As a precedence, TPM doesn't support *AAD* in its sealing API.
  - *AAD* can still be retrieved, even though `oe_unseal()` doesn't return their addresses, as *AAD* follows the cipher text immediately and occupies the rest of the blob in Intel's sealed blob format.
  - Sealed blobs created `oe_seal()` can be opened by the Intel SGX SDK, except that they will never contain *AAD*.

### What cipher mode to use in sealing?

Some cipher modes supporting *AEAD* are listed below. Please note that any mode other than *GCM* will break interoperability with the Intel SGX SDK.

- [ ] *CCM* - slower than *GCM*
- [X] *GCM*
- [ ] *OCB* - patented (expired?)

(**Decision?**) What *IV* (*Initial Vector*) to use for *GCM* encryption?

- [X] Constant 0<sup>96</sup>
  - Interoperability - This is the behavior of the Intel SGX SDK.
  - Key collisions across enclaves - There shall not be 2<sup>64</sup>+ blobs created **globally**.
- [ ] Enclave specific - e.g., using first 96 bits of `MRENCLAVE`
  - `oe_unseal()` can open Intel blobs but Intel cannot unseal blobs created by `oe_seal()`.
  - Key collisions in one enclave - There shall not be 2<sup>64</sup>+ blobs created **per enclave**.
- [ ] Random *IV* - Recommended
  - `oe_unseal()` can open Intel blobs but Intel cannot unseal blobs created by `oe_seal()`.
  - Collisions of both key and *IV* will be a lot rarer.

## Authors

Cedric Xing (cedric.xing@intel.com)
