# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/sealing.edl)

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/sealing/same_enclave sealing_host 
  sealing_enc_a_v1_signed $<TARGET_FILE:sealing_enc_a_v1_signed>)
add_enclave_test(tests/sealing/same_signer sealing_host 
  sealing_enc_a_v1_signed $<TARGET_FILE:sealing_enc_a_v2_signed> 1)
add_enclave_test(tests/sealing/different_signer sealing_host 
  sealing_enc_a_v1_signed $<TARGET_FILE:sealing_enc_b_signed> 0)
