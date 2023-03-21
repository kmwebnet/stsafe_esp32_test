/**
  ******************************************************************************
  * @file    stsafea_ops.h
  * @author  kmwebnet
  * @version V1.0.0
  * @brief   STSAFE-A110 operation
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


#ifndef STSAFEA_OPS
#define STSAFEA_OPS

#include "stsafea_types.h"
#include "stsafea_core.h"

#define HEADER_BYTES 4

StSafeA_ResponseCode_t ST_RetrieveCert(StSafeA_Handle_t *pStSafeA, uint8_t zone, uint16_t offset, uint8_t *retrieved_Object, uint16_t *Object_size);
StSafeA_ResponseCode_t check_local_envelope_key(StSafeA_Handle_t *handle);
StSafeA_ResponseCode_t check_host_keys(StSafeA_Handle_t *handle);

#endif //STSAFE_OPS;