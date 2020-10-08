# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT sealing_args.h sealing_t.h sealing_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --trusted ${EDL_FILE}
    --search-path ${PROJECT_SOURCE_DIR}/include ${DEFINE_OE_SGX})

add_custom_command(
  OUTPUT a-private.pem
  COMMAND openssl genrsa -out a-private.pem -3 3072)

add_enclave(
  TARGET
  sealing_enc_a_v1
  UUID
  e234fd12-70ae-45b0-b49a-c3daef8b0ce3
  KEY
  ${CMAKE_CURRENT_BINARY_DIR}/a-private.pem
  CONFIG
  ${CMAKE_CURRENT_SOURCE_DIR}/v1.conf
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/sealing_t.c)

add_enclave(
  TARGET
  sealing_enc_a_v2
  UUID
  d7d767f6-cd49-4ee4-b1fb-d993d5e964ca
  KEY
  ${CMAKE_CURRENT_BINARY_DIR}/a-private.pem
  CONFIG
  ${CMAKE_CURRENT_SOURCE_DIR}/v2.conf
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/sealing_t.c)

add_enclave(
  TARGET
  sealing_enc_b
  UUID
  eea49f43-efe7-4f13-ab7e-d671dc73dc04
  CONFIG
  ${CMAKE_CURRENT_SOURCE_DIR}/v1.conf
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/sealing_t.c)

enclave_include_directories(sealing_enc_a_v1 PRIVATE 
                            ${CMAKE_CURRENT_BINARY_DIR})
enclave_include_directories(sealing_enc_a_v2 PRIVATE 
                            ${CMAKE_CURRENT_BINARY_DIR})
enclave_include_directories(sealing_enc_b PRIVATE 
                            ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(sealing_enc_a_v1 oelibc)
