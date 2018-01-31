#ifndef MIBLE_BEACON_H__
#define MIBLE_BEACON_H__

#include "mible_api.h"
#include "mible_log.h"
#include "mible_port.h"
#include "mible_type.h"
#include "stdio.h"
#include "string.h"

#define MIBLE_SRV_DATA_UUID                         0XFE95
#define MIBLE_MANUFACTURER_UUID						0X038F

#define MIBLE_MAX_ADV_LENGTH						31

typedef struct {
	uint8_t			time_protocol		:1;
	uint8_t			reserved1			:1;
	uint8_t			reserved2           :1;
	uint8_t			is_encrypt          :1;

	uint8_t			mac_include         :1;
	uint8_t			cap_include         :1;
	uint8_t			obj_include         :1;
	uint8_t			reserved3 		   	:1;

	uint8_t			reserved4           :1;
	uint8_t			bond_confirm        :1;
	uint8_t			secure_auth         :1;
	uint8_t			secure_login        :1;

	uint8_t			version      		:4;
} mibeacon_frame_ctrl_t;

typedef struct {
	uint16_t    	type;
	uint8_t         len;
	uint8_t         val[17];
 } mibeacon_obj_t;

typedef struct {
	uint8_t 		connectable : 1;
	uint8_t 		centralable : 1;
	uint8_t 		encryptable : 1;
	uint8_t 		bondAbility : 2;
	uint8_t 		reserved    : 3;
} mibeacon_capability_t;

typedef struct {
	mibeacon_frame_ctrl_t 	frame_ctrl;
	uint16_t              	pid;
	mible_addr_t           *p_mac;
	mibeacon_capability_t  *p_capability;
	mibeacon_obj_t         *p_obj;
	uint8_t                 obj_num;
} mibeacon_config_t;

mible_status_t mibeacon_init(uint16_t pid, uint8_t *key, uint8_t *mac);

mible_status_t mibeacon_data_set(mibeacon_config_t const * const config,
		uint8_t *p_output, uint8_t *p_output_len);

mible_status_t mible_service_data_set(mibeacon_config_t const * const config,
		uint8_t *p_output, uint8_t *p_output_len);

mible_status_t mible_manu_data_set(mibeacon_config_t const * const config,
		uint8_t *p_output, uint8_t *p_output_len);
#endif
