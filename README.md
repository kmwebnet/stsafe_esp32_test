# STSAFE-esp32-test

This communicates STMicro STSAFE-A110(SPL02) secure chip from ESP32 and test the functions.    
(Random number, extract provisioned certificate, generate key, ECDH calculation, sign)　　

# Requirements

Platformio(PLATFORM: Espressif 32 6.1.0) with VS Code environment.  
install "Espressif 32" platform definition on Platformio  

# Environment reference
  
  Espressif ESP32-DevkitC  
  this project initialize I2C port   
  pin assined as below:  

      I2C SDA GPIO_NUM_21  
      I2C SCL GPIO_NUM_22  
      RST_PIN GPIO_NUM_23  
       
  STSAFE-A110(SPL02)   

# Usage  

"git clone --recursive " on your target directory. and you need to change a serial port number which actually connected to ESP32 in platformio.ini.    

# Run this project

just execute "Upload" on Platformio.   

# License

If a license is stated in the source code, that license is applied, otherwise the MIT license is applied, see LICENSE.  
