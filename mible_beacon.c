#include <string.h>

#include "mible_beacon.h"
#include "mible_api.h"

#include "ccm.h"

#undef  MI_LOG_MODULE_NAME
#define MI_LOG_MODULE_NAME "MIBEACON"
#include "mible_log.h"

#define LO_BYTE(val) (uint8_t)val
#define HI_BYTE(val) (uint8_t)(val>>8)

static uint8_t frame_cnt;
static uint8_t m_beacon_key_is_vaild;
static uint8_t beacon_key[16];
static struct {
	uint8_t  mac[6];
	uint16_t pid;
	uint8_t  cnt;
	uint8_t  rand[3];
} beacon_nonce;

static int event_encode(mibeacon_obj_t *p_obj, uint8_t *output)
{
	output[0] = p_obj->type;
	output[1] = p_obj->type >> 8;
	output[2] = p_obj->len;
	memcpy(output+3, p_obj->val, p_obj->len);
	return 0;
}

static int calc_objs_bytes(mibeacon_obj_t *p_obj, uint8_t num)
{
	uint8_t sum = num * 3;
	for (uint8_t i = 0; i < num; i++)
		sum += p_obj[i].len;

	return sum;
}

void set_beacon_key(uint8_t *p_key)
{
	mible_gap_address_get(beacon_nonce.mac);
	memcpy(beacon_key, p_key, sizeof(beacon_key));
	m_beacon_key_is_vaild = 1;
}

mible_status_t mibeacon_init(uint16_t pid, uint8_t *key, uint8_t *mac)
{
	if (key == NULL || mac == NULL)
		return MI_ERR_INVALID_PARAM;

	beacon_nonce.pid = pid;
	memcpy(beacon_nonce.mac, mac, 6);
	memcpy(beacon_key, key, 16);
	return MI_SUCCESS;
}

/*
 * @brief 	set mibeacon service data  
 * @param 	[in] config: mibeacon configure data 
 *  		[out] p_output: pointer to mibeacon data  (watch out array out of bounds) 
 * 			[out] p_output_len: pointer to mibeacon data length 
 * @return  MI_ERR_INVALID_PARAM: 	Invalid pointer supplied or mismatched frmctl.  
 * 			MI_ERR_INVALID_LENGTH:	Adv data length exceeds MIBLE_MAX_ADV_LENGTH-7.
 *          MI_ERR_INTERNAL:        Not found rand num used to encrypt data.
 * 			MI_SUCCESS:				Set successfully.
 * */
mible_status_t mibeacon_data_set(mibeacon_config_t const * const config, 
		uint8_t *output, uint8_t *output_len)
{
	mibeacon_frame_ctrl_t *p_frame_ctrl = (void*)output;
	uint8_t len, *p_obj_head, *head = output;
	uint32_t errno;

	if (config == NULL || output == NULL || output_len == NULL) {
		*output_len = 0;
		return MI_ERR_INVALID_PARAM;
	}

	/*  encode frame_ctrl and product_id */
	memcpy(output, (uint8_t*)config, 4);
	output     += 4;

	/*  encode frame cnt */
	output[0] = (uint8_t) ++frame_cnt;
	output   += 1;

	/*  encode gap mac */
	if (config->p_mac != NULL) {
		p_frame_ctrl->mac_include = 1;
		memcpy(output, config->p_mac, 6);
		output += 6;
	}

	/*  encode capability */
	if (config->p_capability != NULL) {
		p_frame_ctrl->cap_include = 1;
		memcpy(output, config->p_capability, 1);
		output += 1;
	}
	
	len = output - head;
	len += calc_objs_bytes(config->p_obj, config->obj_num);
	len += p_frame_ctrl->is_encrypt ? 7 : 0;

	if (len > MIBLE_MAX_ADV_LENGTH)
		return MI_ERR_DATA_SIZE;

	if (config->p_obj != NULL) {
		p_frame_ctrl->obj_include = 1;
		p_obj_head = output;
		for (uint8_t i = 0, max = config->obj_num; i < max; i++) {
			event_encode(config->p_obj + i, output);
			output += 3 + config->p_obj[i].len;
		}
	} else {
		/* NO object need to be encrypted. */
		len -= p_frame_ctrl->is_encrypt ? 7 : 0;
		p_frame_ctrl->is_encrypt = 0;
		*output_len = len;
		return MI_SUCCESS;
	}

	if (p_frame_ctrl->is_encrypt == 1 && m_beacon_key_is_vaild) {
		beacon_nonce.cnt = frame_cnt;
		errno = mible_rand_num_generator(beacon_nonce.rand, 3);
		
		if (errno != MI_SUCCESS) {
			MI_ERR_CHECK(errno);
			return MI_ERR_INTERNAL;
		}

		uint8_t mic[4];
		uint8_t aad = 0x11;
		uint8_t objs_len = output - p_obj_head;
		aes_ccm_encrypt_and_tag(beacon_key,
	                (uint8_t*)&beacon_nonce, sizeof(beacon_nonce),
	                                   &aad, sizeof(aad),
		               (uint8_t*)p_obj_head, objs_len,
		               (uint8_t*)p_obj_head,
	                                    mic, 4);
		
		memcpy(output, beacon_nonce.rand, 3);
		output += 3;

		memcpy(output, mic, sizeof(mic));
    } else {
        p_frame_ctrl->is_encrypt = 0;
        return MI_ERR_INTERNAL;
	}

	*output_len = len;

	return MI_SUCCESS;
}

/*
 * @brief 	Set <service data>. 
 * @param 	[in] config: mibeacon configure data 
 *  		[out] p_output: pointer to mibeacon data  (watch out array out of bounds) 
 * 			[out] p_output_len: pointer to mibeacon data length 
 * @return 	MI_ERR_INVALID_PARAM: 	Invalid pointer supplied.  
 * 			MI_SUCCESS:				Set successfully.
 *          MI_ERR_DATA_SIZE:       Adv bytes excceed the maximun.
 * */
mible_status_t mible_service_data_set(mibeacon_config_t const * const config,
		uint8_t *p_output, uint8_t *p_output_len)
{
	uint32_t errno;
	uint8_t data_len;

// check input
	if(config == NULL || p_output == NULL || p_output_len == NULL){
		MI_LOG_ERROR("error parameters.\n");
		return MI_ERR_INVALID_PARAM;
	}

	p_output[1] = 0x16;
	p_output[2] = LO_BYTE(MIBLE_SRV_DATA_UUID);
	p_output[3] = HI_BYTE(MIBLE_SRV_DATA_UUID);
	errno = mibeacon_data_set(config, &p_output[4], &data_len);
	p_output[0] = 3 + data_len;

	if (errno != MI_SUCCESS) {
		MI_ERR_CHECK(errno);
		return MI_ERR_DATA_SIZE;
	}
	
	*p_output_len = 4 + data_len;

	return MI_SUCCESS;
}

/*
 * @brief 	Set <manufacturer> data. 
 * @param 	[in] config: mibeacon configure data 
 *  		[out] p_output: pointer to mibeacon data  (watch out array out of bounds) 
 * 			[out] p_output_len: pointer to mibeacon data length  
 * @return  MI_ERR_INVALID_PARAM: 	Invalid pointer supplied.  
 * 			MI_ERR_INVALID_LENGTH:	Data length exceeds MIBLE_MAX_ADV_LENGTH. 
 * 			MI_SUCCESS:				Set successfully.
 * @Note: 	p_obj[obj_num-1]
 * */
mible_status_t mible_manu_data_set(mibeacon_config_t const * const config,
		uint8_t *p_output, uint8_t *p_output_len)
{
	uint32_t errno;
	uint8_t data_len;
// check input
	if(config == NULL || p_output == NULL || p_output_len == NULL){
		MI_LOG_ERROR("error parameters.\n");
		return MI_ERR_INVALID_PARAM;
	}

	p_output[1] = 0xFF;
	p_output[2] = LO_BYTE(MIBLE_MANUFACTURER_UUID);
	p_output[3] = HI_BYTE(MIBLE_MANUFACTURER_UUID);
	errno = mibeacon_data_set(config, &p_output[4], &data_len);
	p_output[0] = 3 + data_len;
	
	if (errno != MI_SUCCESS) {
		MI_ERR_CHECK(errno);
		return MI_ERR_DATA_SIZE;
	}

	*p_output_len = 4 + data_len;

	return MI_SUCCESS;
}



