/**
  ******************************************************************************
  * @file    stsafea_service_interface.c
  * @author  SMD application team
  * @version V3.3.1
  * @brief   Service Interface file to support the hardware services required by the
  *          STSAFE-A Middleware and offered by the specific HW, Low Level library
  *          selected by the user. E.g.:
  *           + IOs
  *           + Communication Bus (e.g. I2C)
  *           + Timing delay
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; COPYRIGHT 2016 STMicroelectronics</center></h2>
  * copyright 2023 kmwebnet for ESP32
  * 
  * This software is licensed under terms that can be found in the LICENSE file in
  * the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */


/* Includes ------------------------------------------------------------------*/
#include "stsafea_service.h"
#include "stsafea_interface_conf.h"
#include <driver/i2c.h>
#include "freertos/FreeRTOS.h"
#include "driver/gpio.h"
#include "esp32/rom/crc.h"

/* Private typedef -----------------------------------------------------------*/

/* Private define ------------------------------------------------------------*/
#define STSAFEA_DEVICE_ADDRESS             0x0020

#define SDA_PIN                            21
#define SCL_PIN                            22
#define RST_PIN                            23
#define ACK_CHECK_EN                       0x1
#define ACK_CHECK_DIS                      0x0
#define ACK_VAL                            0x0
#define NACK_VAL                           0x1


/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
i2c_config_t conf;
/* Private function prototypes -----------------------------------------------*/
int32_t I2C_Init(void);
int32_t I2C_DeInit(void);
int32_t I2C_Send(uint16_t DevAddr, uint8_t *pData, uint16_t Length);
int32_t I2C_Recv(uint16_t DevAddr, uint8_t *pData, uint16_t Length);

/* Private functions ---------------------------------------------------------*/

/**
  * @brief  I2C_Init
  *         init BUS.
  * @retval STSAFEA_HW_OK   : on success
  * @retval STSAFEA_HW_NACK : on bus NACK
  * @retval STSAFEA_HW_ERR  : on bus error
  */
int32_t I2C_Init(void)
{


    esp_err_t rc;
        conf.mode = I2C_MODE_MASTER;
        conf.sda_io_num = SDA_PIN;
        conf.scl_io_num = SCL_PIN;
        conf.sda_pullup_en = GPIO_PULLUP_ENABLE;
        conf.scl_pullup_en = GPIO_PULLUP_ENABLE;
        conf.master.clk_speed = 100000; 
        rc = i2c_param_config(I2C_NUM_0, &conf);
        rc = i2c_driver_install(I2C_NUM_0, I2C_MODE_MASTER, 0, 0, 0);



    if (rc == ESP_OK)
    {
        return STSAFEA_BUS_OK;
    }
    else
    {
        return STSAFEA_BUS_ERR;
    }
}


/**
  * @brief  I2C_DeInit
  *         Deinit BUS.
  * @retval STSAFEA_HW_OK   : on success
  * @retval STSAFEA_HW_NACK : on bus NACK
  * @retval STSAFEA_HW_ERR  : on bus error
  */
int32_t I2C_DeInit(void)
{
    i2c_driver_delete(I2C_NUM_0);
    return STSAFEA_BUS_OK;
}


/**
  * @brief  I2C_Send
  *         send data through BUS.
  * @param  DevAddr : Device address on Bus.
  * @param  pData   : Pointer to data buffer to write
  * @param  Length  : Data Length
  * @retval STSAFEA_HW_OK   : on success
  * @retval STSAFEA_HW_NACK : on bus NACK
  * @retval STSAFEA_HW_ERR  : on bus error
  */
int32_t I2C_Send(uint16_t DevAddr, uint8_t *pData, uint16_t Length)
{
    esp_err_t rc = ESP_OK;
    i2c_cmd_handle_t cmdhandle = i2c_cmd_link_create();
    (void)i2c_master_start(cmdhandle);
    (void)i2c_master_write_byte(cmdhandle, (uint8_t)DevAddr | I2C_MASTER_WRITE, ACK_CHECK_EN);
    (void)i2c_master_write(cmdhandle, pData, Length, ACK_CHECK_EN);
    (void)i2c_master_stop(cmdhandle);
    rc = i2c_master_cmd_begin(I2C_NUM_0, cmdhandle,1000 / portTICK_PERIOD_MS);
    (void)i2c_cmd_link_delete(cmdhandle);
  if (rc == ESP_FAIL)
  {
    return STSAFEA_BUS_NACK;
  }

  if (rc == ESP_OK)
  {
    return STSAFEA_BUS_OK;
  }

  return STSAFEA_BUS_ERR;
}

/**
  * @brief  I2C_Recv
  *         Receive data through BUS.
  * @param  DevAddr Device address on Bus.
  * @param  Reg    The target register address to read
  * @param  pData  Pointer to data buffer to read
  * @param  Length Data Length
  * @retval BSP status
  */
int32_t I2C_Recv(uint16_t DevAddr, uint8_t *pData, uint16_t Length)
{
    esp_err_t rc;
    i2c_cmd_handle_t cmdhandle = i2c_cmd_link_create();
    i2c_master_start(cmdhandle);
    i2c_master_write_byte(cmdhandle, (uint8_t)DevAddr | I2C_MASTER_READ, ACK_CHECK_EN);
    i2c_master_read(cmdhandle, pData, Length, I2C_MASTER_LAST_NACK);
	  i2c_master_stop(cmdhandle);

    rc = i2c_master_cmd_begin(I2C_NUM_0, cmdhandle, 1000 / portTICK_PERIOD_MS);
    if (ESP_OK != rc)
    {
        if (ESP_FAIL == rc)
        {
            (void)i2c_cmd_link_delete(cmdhandle);
            return STSAFEA_BUS_NACK;
        }
        (void)i2c_cmd_link_delete(cmdhandle);
        return STSAFEA_BUS_ERR;
    }      
    (void)i2c_cmd_link_delete(cmdhandle);
    
    // for debug
    /*
    printf("I2C recv: addr: %d, length: %d\n", (uint8_t)DevAddr, Length);

    for(int j = 0; j < Length; j++){
      printf("%02x ", pData[j]);
      }
    printf("\n");
    */

    return STSAFEA_BUS_OK;
}


int32_t HW_IO_Init(void)
{
    gpio_set_direction(RST_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(RST_PIN, 0);
    vTaskDelay(1 / portTICK_PERIOD_MS);
    gpio_set_level(RST_PIN, 1);
    vTaskDelay(40 / portTICK_PERIOD_MS);

return STSAFEA_BUS_OK;
}

void HAL_Delay(uint32_t msDelay)
{
    vTaskDelay(msDelay / portTICK_PERIOD_MS);
}

int32_t CRC16X25_Init(void)
{
return STSAFEA_BUS_OK;
}

uint32_t CRC_Compute(uint8_t *pData1, uint16_t Length1, uint8_t *pData2, uint16_t Length2)
{
uint16_t crc = 0;

crc = crc16_le((uint16_t)~(0xffff), pData1, (uint32_t)Length1);
crc = crc16_le(crc, pData2, (uint32_t)Length2);
crc = SWAP2BYTES(crc);

return (uint32_t)(~crc)^0xffff;
}

/**
  * @brief  StSafeA_HW_Probe
  *         Configure STSAFE IO and Bus operation functions to be implemented at User level
  * @param  Ctx the STSAFE IO context
  * @retval 0 in case of success, an error code otherwise
  */
int8_t StSafeA_HW_Probe(void *pCtx)
{
  STSAFEA_HW_t *HwCtx = (STSAFEA_HW_t *)pCtx;


  HwCtx->IOInit     = HW_IO_Init;
  HwCtx->BusInit    = I2C_Init;
  HwCtx->BusDeInit  = I2C_DeInit;
  HwCtx->BusSend    = I2C_Send;
  HwCtx->BusRecv    = I2C_Recv;
  HwCtx->CrcInit    = CRC16X25_Init;
  HwCtx->CrcCompute = CRC_Compute;
  HwCtx->TimeDelay  = HAL_Delay;
  HwCtx->DevAddr    = STSAFEA_DEVICE_ADDRESS;

  return STSAFEA_BUS_OK;
}


