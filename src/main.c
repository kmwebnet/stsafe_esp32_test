/**
 ******************************************************************************
 * @file    stsafea_esp32 test
 * @author  kmwebnet
 * @version V1.0.0
 * @brief   STSAFE-A110 test operation
 ******************************************************************************
 * @attention
 *
 * COPYRIGHT 2023 kmwebnet <kmwebnet@gmail.com>
 *
 * This software is licensed under terms that can be found in the LICENSE file in
 * the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */
#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "base64.h"

#define STSAFE_A110

#include "stsafeaxxx.h"
#include "stsafea_conf.h"
#include "stsafea_types.h"
#include "stsafea_core.h"
#include "stsafea_crypto.h"
#include "stsafe_ops.h"

#include "mbedtls/sha256.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

StSafeA_Handle_t stsafea_handle;
uint8_t a_rx_tx_stsafea_data[STSAFEA_BUFFER_MAX_SIZE];
StSafeA_ResponseCode_t StatusCode;

void app_main()
{

  StatusCode = StSafeA_Init(&stsafea_handle, a_rx_tx_stsafea_data);
  if (StatusCode == STSAFEA_OK)
  {
    printf("StSafeA_Init Success\n\n");
  }

  uint8_t a_echo_data[3] = {0x01U, 0x02U, 0x03U};
  StSafeA_LVBuffer_t out_echo;
  /*
  uint8_t data[10];
  uint8_t datalen = 10;
  out_echo.Data = data;
  out_echo.Length = datalen;
  */
  StatusCode = StSafeA_Echo(&stsafea_handle, a_echo_data, (uint16_t)(sizeof(a_echo_data)), &out_echo, STSAFEA_MAC_NONE);
  if (StatusCode == STSAFEA_OK)
  {
    printf("StSafeA_Echo Success\n\n");
  }

  StSafeA_LVBuffer_t TrueRandom;
  /*
  uint8_t trdata[32];
  uint8_t trdatalen = 32;
  TrueRandom.Data = trdata;
  TrueRandom.Length = trdatalen;
  */
  StatusCode = StSafeA_GenerateRandom(&stsafea_handle, STSAFEA_EPHEMERAL_RND, 32, &TrueRandom, STSAFEA_MAC_NONE);

  if (StatusCode == STSAFEA_OK)
  {
    printf("Random data:\n");
    for (int i = 0; i < 2; i++)
    {
      for (int j = 0; j < 16; j++)
      {
        printf("%02x ", TrueRandom.Data[i * 16 + j]);
      }
      printf("\n");
    }
    printf("StSafeA_GenerateRandom Success\n\n");
  }

  // read out zone 0 certificate

  uint8_t cert[1000];
  uint16_t certlen = 0;

  StatusCode = ST_RetrieveCert(&stsafea_handle, 0, 0, cert, &certlen);
  if (StatusCode == STSAFEA_OK)
  {
    printf("ST_RetrieveCert Success\n\n");
    /* Print out the cert */
    printf("-----BEGIN CERTIFICATE-----\n%s-----END CERTIFICATE-----\n", base64_encode(cert, certlen, NULL));
  }
  else
  {
    printf("ST_RetrieveCert Fail\n");
  }

  StatusCode = check_local_envelope_key(&stsafea_handle);
  if (StatusCode == STSAFEA_OK)
  {
    printf("check_local_envelope_key Success\n\n");
  }
  StatusCode = check_host_keys(&stsafea_handle);
  if (StatusCode == STSAFEA_OK)
  {
    printf("check_host_keys Success\n\n");
  }
  printf("status code:0x%x\n", StatusCode);

  StSafeA_LVBuffer_t PubCX, PubCY;
  uint8_t PointReprensentationId = 0;

  printf("StSafeA_GenerateKeyPair Test. Generate Ephemeral key pair...\n\n");

  StatusCode = StSafeA_GenerateKeyPair(&stsafea_handle, STSAFEA_KEY_SLOT_EPHEMERAL, 0xFFFF, 0,
                                       (STSAFEA_PRVKEY_MODOPER_AUTHFLAG_CMD_RESP_SIGNEN |
                                        STSAFEA_PRVKEY_MODOPER_AUTHFLAG_MSG_DGST_SIGNEN |
                                        STSAFEA_PRVKEY_MODOPER_AUTHFLAG_KEY_ESTABLISHEN),
                                       STSAFEA_NIST_P_256, STSAFEA_XYRS_ECDSA_SHA256_LENGTH,
                                       &PointReprensentationId,
                                       &PubCX, &PubCY,
                                       STSAFEA_MAC_HOST_RMAC);
  if (StatusCode == STSAFEA_OK)
  {
    printf("PubCX data:\n");
    for (int i = 0; i < PubCX.Length / 16; i++)
    {
      for (int j = 0; j < 16; j++)
      {
        printf("%02x ", PubCX.Data[i * 16 + j]);
      }
      printf("\n");
    }
    printf("PubCY data:\n");
    for (int i = 0; i < PubCY.Length / 16; i++)
    {
      for (int j = 0; j < 16; j++)
      {
        printf("%02x ", PubCY.Data[i * 16 + j]);
      }
      printf("\n");
    }

    printf("StSafeA_GenerateKeyPair Success\n\n");
  }
  else
  {
    printf("StSafeA_GenerateKeyPair fail:0x%x\n\n", StatusCode);
    return;
  }
  // ECDH camputation both secure element and host side and verify these are the same.

  printf("StSafeA_EstablishKey Test. ECDH calculation host & Secure element...\n\n");

  static const uint8_t host_private_key[] = {
      0xED, 0x2C, 0xA6, 0xE4, 0x06, 0xEA, 0xE1, 0xD7, 0x3E, 0x4A, 0x1B, 0x24, 0x5D, 0xF0, 0xF0, 0x60,
      0xEC, 0xC3, 0xE5, 0x3F, 0x13, 0xE8, 0x09, 0xC5, 0x53, 0x51, 0x23, 0xE3, 0xB5, 0x71, 0x2F, 0xD4};
  static const uint8_t host_public_x_key[] = {
      0xAB, 0x06, 0x01, 0x5B, 0x1B, 0xEC, 0x73, 0xA1, 0x25, 0x4A, 0xA1, 0x84, 0x66, 0x0D, 0xB9, 0x9F,
      0xAE, 0xC9, 0x60, 0x3F, 0xE8, 0x9D, 0xD0, 0x74, 0x54, 0xE7, 0xD1, 0x3D, 0x30, 0x1D, 0xCF, 0x25};
  static const uint8_t host_public_y_key[] = {
      0xA6, 0xF7, 0x32, 0x40, 0xF7, 0x9D, 0x81, 0x8A, 0xB0, 0x72, 0x3C, 0x8E, 0x1C, 0xE5, 0xDC, 0xCB,
      0x07, 0x72, 0x0A, 0x2A, 0x7A, 0x71, 0xC5, 0x26, 0x3B, 0xC9, 0x89, 0xD9, 0x1E, 0xCD, 0x98, 0x23};

  mbedtls_ecdh_context ctx_host;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  uint8_t pms[32];

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

  mbedtls_ecdh_init(&ctx_host);
  mbedtls_ecp_group_load(&ctx_host.private_ctx.private_mbed_ecdh.private_grp, MBEDTLS_ECP_DP_SECP256R1);

  // Host Side computation

  // set Host private key to host
  mbedtls_mpi_read_binary(&ctx_host.private_ctx.private_mbed_ecdh.private_d, host_private_key, 32);
  // set STSAFE public key to host
  mbedtls_mpi_read_binary(&ctx_host.private_ctx.private_mbed_ecdh.private_Qp.private_X, PubCX.Data, 32);
  mbedtls_mpi_read_binary(&ctx_host.private_ctx.private_mbed_ecdh.private_Qp.private_Y, PubCY.Data, 32);
  mbedtls_mpi_lset(&ctx_host.private_ctx.private_mbed_ecdh.private_Qp.private_Z, 1);

  mbedtls_ecdh_compute_shared(&ctx_host.private_ctx.private_mbed_ecdh.private_grp,
                              &ctx_host.private_ctx.private_mbed_ecdh.private_z,
                              &ctx_host.private_ctx.private_mbed_ecdh.private_Qp,
                              &ctx_host.private_ctx.private_mbed_ecdh.private_d,
                              mbedtls_ctr_drbg_random, &ctr_drbg);

  mbedtls_mpi_write_binary(&ctx_host.private_ctx.private_mbed_ecdh.private_z, pms, 32);

  printf("pms data:\n");

  for (int i = 0; i < 2; i++)
  {
    for (int j = 0; j < 16; j++)
    {
      printf("%02x ", pms[i * 16 + j]);
    }
    printf("\n");
  }

  StSafeA_LVBuffer_t pubX, pubY;
  pubX.Data = host_public_x_key;
  pubX.Length = 32;
  pubY.Data = host_public_y_key;
  pubY.Length = 32;
  StSafeA_SharedSecretBuffer_t pms_se;

  StatusCode = StSafeA_EstablishKey(&stsafea_handle, STSAFEA_KEY_SLOT_EPHEMERAL, &pubX, &pubY,
                                    STSAFEA_XYRS_ECDSA_SHA256_LENGTH,
                                    &pms_se,
                                    STSAFEA_MAC_HOST_CMAC, STSAFEA_ENCRYPTION_NONE);
  if (StatusCode == STSAFEA_OK)
  {
    printf("pms_se data:\n");
    for (int i = 0; i < pms_se.SharedKey.Length / 16; i++)
    {
      for (int j = 0; j < 16; j++)
      {
        printf("%02x ", pms_se.SharedKey.Data[i * 16 + j]);
      }
      printf("\n");
    }

    printf("StSafeA_EstablishKey Success\n\n");
  }
  else
  {
    printf("StSafeA_EstablishKey fail:0x%x\n\n", StatusCode);
    return;
  }

  if (memcmp(pms, pms_se.SharedKey.Data, 32))
  {
    printf("StSafeA_EstablishKey fail:both of keys don't match. \n\n");
    return;
  }
  else
  {
    printf("both of keys match as expected.\n\n");
  }

  // sign test with slot0 private key due to limitation the ephemeral key is not allowed making signature.

  printf("Sign hashed message -example- test with pre-provisioned key pair...\n\n");
  StSafeA_LVBuffer_t OutR, OutS;
  char *plain_text = "example";
  uint8_t hash[32] = {0};

  mbedtls_sha256_context sha_ctx;

  mbedtls_sha256_init(&sha_ctx);
  mbedtls_sha256_starts(&sha_ctx, 0);
  mbedtls_sha256_update(&sha_ctx, (uint8_t *)plain_text, sizeof(plain_text));
  mbedtls_sha256_finish(&sha_ctx, hash);
  mbedtls_sha256_free(&sha_ctx);

  printf("hashed data:\n");
  for (int i = 0; i < 2; i++)
  {
    for (int j = 0; j < 16; j++)
    {
      printf("%02x ", hash[i * 16 + j]);
    }
    printf("\n");
  }

  StatusCode = StSafeA_GenerateSignature(&stsafea_handle, STSAFEA_KEY_SLOT_0, hash, STSAFEA_SHA_256,
                                         STSAFEA_XYRS_ECDSA_SHA256_LENGTH,
                                         &OutR, &OutS,
                                         STSAFEA_MAC_NONE, STSAFEA_ENCRYPTION_NONE);
  if (StatusCode == STSAFEA_OK)
  {
    printf("OutR data:\n");
    for (int i = 0; i < OutR.Length / 16; i++)
    {
      for (int j = 0; j < 16; j++)
      {
        printf("%02x ", OutR.Data[i * 16 + j]);
      }
      printf("\n");
    }
    printf("OutS data:\n");
    for (int i = 0; i < OutS.Length / 16; i++)
    {
      for (int j = 0; j < 16; j++)
      {
        printf("%02x ", OutS.Data[i * 16 + j]);
      }
      printf("\n");
    }

    printf("StSafeA_GenerateSignature Success\n\n");
  }
  else
  {
    printf("StSafeA_GenerateSignature fail:0x%x\n\n", StatusCode);
    return;
  }
}