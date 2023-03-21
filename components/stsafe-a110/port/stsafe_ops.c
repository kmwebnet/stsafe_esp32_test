/**
  ******************************************************************************
  * @file    stsafea_ops.c
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

#include <stdio.h>
#include <string.h>
#include "stsafe_ops.h"
#include "stsafea_service.h"


static StSafeA_ResponseCode_t ST_GetCertSize(StSafeA_Handle_t *pStSafeA, uint8_t zone, uint16_t offset, uint16_t *Cert_size)
{
  StSafeA_ResponseCode_t status = STSAFEA_OK;

  StSafeA_LVBuffer_t sts_read;
  uint8_t data_sts_read[HEADER_BYTES];
  uint16_t calculated_Cert_size = 0;

  sts_read.Length = HEADER_BYTES;
  sts_read.Data = data_sts_read;

  // Extract the first 4 bytes of the STSAFE A110 X509 Cert which provide the size of the Cert.
  status = StSafeA_Read(pStSafeA, 0, 0, STSAFEA_AC_ALWAYS, zone, offset, HEADER_BYTES, HEADER_BYTES, &sts_read, STSAFEA_MAC_NONE);

  if (status == STSAFEA_OK)
  {
    switch (sts_read.Data[1])
    {
      case 0x81U:
	calculated_Cert_size = (uint16_t) sts_read.Data[2] + 3U;
	break;

      case 0x82U:
	calculated_Cert_size = (((uint16_t) sts_read.Data[2]) << 8) + sts_read.Data[3] + 4U;
	break;

      default:
	if (sts_read.Data[1] < 0x81U)
	{
	  calculated_Cert_size = sts_read.Data[1];
	}
	break;
    }

    if (calculated_Cert_size == 0)
    {
      return STSAFEA_ENTRY_NOT_FOUND;
    }
  }

  *Cert_size = calculated_Cert_size;

  return status;
}








StSafeA_ResponseCode_t ST_RetrieveCert(StSafeA_Handle_t *pStSafeA, uint8_t zone, uint16_t offset, uint8_t *retrieved_Cert, uint16_t *Cert_size)
{
  uint16_t current_offset = offset;
  uint8_t i;

  StSafeA_ResponseCode_t status = STSAFEA_OK;

  StSafeA_LVBuffer_t sts_read_cert;

  // Get the size of the Cert.
  status = ST_GetCertSize(pStSafeA, zone, offset, Cert_size);

  // Extract the X509 Cert from STSAFE A110 Zone.
  if (status == STSAFEA_OK)
  {
    if (*Cert_size > STSAFEA_BUFFER_DATA_CONTENT_SIZE)
    {

      for (i = 0; i < (*Cert_size / STSAFEA_BUFFER_DATA_CONTENT_SIZE); i++)
      {
	      // Extract the X509 Cert from STSAFE A110 Zone.
	      status = StSafeA_Read(pStSafeA, 0, 0, STSAFEA_AC_ALWAYS, zone, current_offset, STSAFEA_BUFFER_DATA_CONTENT_SIZE, STSAFEA_BUFFER_DATA_CONTENT_SIZE, &sts_read_cert, STSAFEA_MAC_NONE);

	      current_offset += STSAFEA_BUFFER_DATA_CONTENT_SIZE;

	      sts_read_cert.Data += STSAFEA_BUFFER_DATA_CONTENT_SIZE;
	      sts_read_cert.Length = STSAFEA_BUFFER_DATA_CONTENT_SIZE;

	      if (status != STSAFEA_OK) return STSAFEA_ENTRY_NOT_FOUND;

      }

        if (status == STSAFEA_OK)
        {
	        sts_read_cert.Length = *Cert_size % STSAFEA_BUFFER_DATA_CONTENT_SIZE;

	        if (sts_read_cert.Length != 0U)
	        {
	        // Extract the X509 Cert from STSAFE A110 Zone.
	          status = StSafeA_Read(pStSafeA, 0, 0, STSAFEA_AC_ALWAYS, zone, current_offset, (*Cert_size % STSAFEA_BUFFER_DATA_CONTENT_SIZE), (*Cert_size % STSAFEA_BUFFER_DATA_CONTENT_SIZE), &sts_read_cert, STSAFEA_MAC_NONE);

	          if (status != STSAFEA_OK) return STSAFEA_ENTRY_NOT_FOUND;

	        }
        }
    }
    else
    {

      // Extract the X509 Cert from STSAFE A110 Zone.
      status = StSafeA_Read(pStSafeA, 0, 0, STSAFEA_AC_ALWAYS, zone, 0, *Cert_size, *Cert_size, &sts_read_cert, STSAFEA_MAC_NONE);

      if (status != STSAFEA_OK)	return STSAFEA_ENTRY_NOT_FOUND;

    }
  }
  memcpy(retrieved_Cert, sts_read_cert.Data, sts_read_cert.Length);
  return status;
}

StSafeA_ResponseCode_t check_local_envelope_key(StSafeA_Handle_t *handle)
{
  StSafeA_ResponseCode_t status = STSAFEA_OK;
  StSafeA_LocalEnvelopeKeyTableBuffer_t LocalEnvelopeKeyTable;
  StSafeA_LocalEnvelopeKeyInformationRecordBuffer_t LocalEnvelopeInfoSlot0, LocalEnvelopeInfoSlot1;

  printf("Querying the STSAFE A110 slots for local envelope keys presence\r\n\r\n");

  status = StSafeA_LocalEnvelopeKeySlotQuery(handle, &LocalEnvelopeKeyTable, &LocalEnvelopeInfoSlot0, &LocalEnvelopeInfoSlot1, STSAFEA_MAC_NONE);
  if (status != STSAFEA_OK) return status;

  printf("Summary of the %d found Envelope Key Slots:\r\n\r\n", LocalEnvelopeKeyTable.NumberOfSlots);

  printf("| Slot | Key Presence | Key Length |\r\n");
  printf("|   %d  |       %d      |     %2d     |\r\n", LocalEnvelopeInfoSlot0.SlotNumber, LocalEnvelopeInfoSlot0.PresenceFlag, LocalEnvelopeInfoSlot0.KeyLength ? 32 : 16);
  printf("|   %d  |       %d      |     %2d     |\r\n\r\n", LocalEnvelopeInfoSlot1.SlotNumber, LocalEnvelopeInfoSlot1.PresenceFlag, LocalEnvelopeInfoSlot1.KeyLength ? 32 : 16);

  // If not already present, generate a 128-bit local envelope key in local envelope key slot 0.
  if ((status == STSAFEA_OK) && (LocalEnvelopeKeyTable.NumberOfSlots != 0U) && (LocalEnvelopeInfoSlot0.SlotNumber == 0U) && (LocalEnvelopeInfoSlot0.PresenceFlag == 0U))
  {
    printf("Local Envelope Key Slot 0 is empty\r\nCommand the STSAFE A110 to generate a 128-bit local envelope key for slot 0\r\n");

    status = StSafeA_GenerateLocalEnvelopeKey(handle, STSAFEA_KEY_SLOT_0, STSAFEA_KEY_TYPE_AES_128, NULL, 0U, STSAFEA_MAC_NONE);
    if (status != STSAFEA_OK) return status;
  }

  // If not already present, generate a 256-bit local envelope key in local envelope key slot 1.
  if ((status == 0) && (LocalEnvelopeKeyTable.NumberOfSlots != 0U) && (LocalEnvelopeInfoSlot1.SlotNumber == 1U) && (LocalEnvelopeInfoSlot1.PresenceFlag == 0U))
  {
    printf("Local Envelope Key Slot 1 is empty\r\nCommand the STSAFE A110 to generate a 256-bit local envelope key for slot 1\r\n");

    status = StSafeA_GenerateLocalEnvelopeKey(handle, STSAFEA_KEY_SLOT_1, STSAFEA_KEY_TYPE_AES_256, NULL, 0U, STSAFEA_MAC_NONE);
  if (status != STSAFEA_OK) return status;
  }

  return status;
}

StSafeA_ResponseCode_t check_host_keys(StSafeA_Handle_t *handle)
{
  StSafeA_ResponseCode_t status = STSAFEA_OK;
  StSafeA_HostKeySlotBuffer_t HostKeySlot;

// @formatter:off
  uint8_t Host_MAC_Cipher_Key[2U * STSAFEA_HOST_KEY_LENGTH] =
  {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, /* Host MAC key */
    0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88 /* Host cipher key */
  };

  printf("Querying the STSAFE A110 host MAC and cipher keys presence\r\n\r\n");

  /* Check if host cipher key & host MAC key are populated */
  status = StSafeA_HostKeySlotQuery(handle, &HostKeySlot, STSAFEA_MAC_NONE);
  if (status != STSAFEA_OK) return status;

  printf("Summary of the Host Key Slot:\r\n\r\n");

  printf("| Key Presence | Key Length | CMAC Sequence Counter |\r\n");
  printf("|      %d       |     %2d     |  %20d |\r\n\r\n", HostKeySlot.HostKeyPresenceFlag, HostKeySlot.Length ? 32 : 16, (int) HostKeySlot.HostCMacSequenceCounter);

  // Enter if no host MAC and cipher keys are populated.
  if ((status == 0) && (HostKeySlot.HostKeyPresenceFlag == 0U))
  {
    printf("Put the host MAC and cipher keys to the STSAFE A110 Host Key Slot\r\n");

    /* Send both keys to STSAFE */
    status = StSafeA_PutAttribute(handle, STSAFEA_TAG_HOST_KEY_SLOT, Host_MAC_Cipher_Key, 2U * STSAFEA_HOST_KEY_LENGTH, STSAFEA_MAC_NONE);
    if (status != STSAFEA_OK) return status;

  }

  return status;
}


