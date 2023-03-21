#for stsafe MW_V3.3.5

set(COMPONENT_SRCDIRS   "${COMPONENT_DIR}/port"
                        "${COMPONENT_DIR}/mw_V3.3.5/CoreModules/Src"
                        "."
                        )


set(COMPONENT_SRCS      "${COMPONENT_DIR}/port/stsafea_crypto_interface.c"
                        "${COMPONENT_DIR}/port/stsafea_service_interface.c"
                        "${COMPONENT_DIR}/port/stsafea_service.c"
                        "${COMPONENT_DIR}/port/stsafea_crypto.c"
                        "${COMPONENT_DIR}/port/stsafe_ops.c"
                        "${COMPONENT_DIR}/port/stsafea_core.c"
                        )


set(COMPONENT_INCLUDEDIRS   
                        "."
                        "port"
                        "mw_V3.3.5/CoreModules/Inc"
                        )

set(COMPONENT_REQUIRES  "mbedtls" "freertos"  "driver")

set(COMPONENT_EXCLUDE_SRCS
                        "${COMPONENT_DIR}/mw_V3.3.5/CoreModules/Src/stsafea_service.c"
                        "${COMPONENT_DIR}/mw_V3.3.5/CoreModules/Src/stsafea_crypto.c"
                        )

set(COMPONENT_CFLAGS 
                        "ESP32"
                        "STSAFE_A110"
                        )

idf_component_register(
    SRC_DIRS "${COMPONENT_SRCDIRS}" 
    INCLUDE_DIRS "${COMPONENT_INCLUDEDIRS}" 
    REQUIRES "${COMPONENT_REQUIRES}" 
    EXCLUDE_SRCS "${COMPONENT_EXCLUDE_SRCS}"
    )

idf_component_get_property(mbedtls_dir mbedtls COMPONENT_DIR)

target_sources(${COMPONENT_LIB} PRIVATE ${COMPONENT_SRCS})
target_compile_definitions(${COMPONENT_LIB} PRIVATE ${COMPONENT_CFLAGS})
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-unused-variable -Wno-format-truncation -DMBEDTLS_CONFIG_FILE="mbedtls/esp_config.h" -I${mbedtls_dir}/mbedtls/port/include -I${mbedtls_dir}/mbedtls/mbedtls/include -I${mbedtls_dir}/mbedtls/mbedtls/include/mbedtls)

idf_component_get_property(freertos_dir freertos COMPONENT_DIR)
set_source_files_properties(port/stsafea_service_interface.c PROPERTIES COMPILE_FLAGS -I${freertos_dir}/include/freertos)