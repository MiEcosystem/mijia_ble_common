#include <string.h>
#include "mible_beacon.h"
#include "mible_type.h"
#include "mible_api.h"

#include "queue.h"
#include "ccm.h"

#undef  MI_LOG_MODULE_NAME
#define MI_LOG_MODULE_NAME "MIBEACON"
#include "mible_log.h"

#ifdef USE_MI_CONFIG
#include "mi_config.h"
#endif

#ifndef OBJ_QUEUE_SIZE
#define OBJ_QUEUE_SIZE                 8
#endif

#ifndef OBJ_ADV_INTERVAL_MS
#define OBJ_ADV_INTERVAL_MS            200
#endif

#ifndef OBJ_ADV_TIMEOUT_MS
#define OBJ_ADV_TIMEOUT_MS             3000
#endif


#define BLE_UUID_MI_SERVICE                         0xFE95
#define BLE_UUID_COMPANY_ID_XIAOMI                  0x038F
#define REC_ID_SEQNUM                               4

#define LO_BYTE(val) (uint8_t)val
#define HI_BYTE(val) (uint8_t)(val>>8)
#define IS_POWER_OF_TWO(A) ( ((A) != 0) && ((((A) - 1) & (A)) == 0) )
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define MSEC_TO_UNITS(TIME, RESOLUTION) (((TIME) * 1000) / (RESOLUTION))
#define CHECK_ADV_LEN(len)                                                     \
    do {                                                                       \
        if ((len) > MIBLE_MAX_ADV_LENGTH)                                      \
        return MI_ERR_DATA_SIZE;                                               \
    } while(0)


static void * mibeacon_timer;

static struct {
    uint8_t is_init      :1;
    uint8_t is_sending   :1;
    uint8_t is_valid_key :1;
    uint8_t stop_adv_after_sent_out :1;
    uint8_t rfu          :4;
} flags;

static uint8_t beacon_key[16];
static queue_t mi_obj_queue;
static union {
    uint8_t  byte[4];
    uint32_t value;
} seqnum;
static struct {
    uint8_t  mac[6];
    uint16_t pid;
    uint8_t  cnt;
    uint8_t  ext_cnt[3];
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
    // 3 = 2 bytes object ID + 1 byte length
    uint8_t sum = num * 3;

    if (p_obj == NULL)
        return 0;

    for (uint8_t i = 0; i < num; i++)
        sum += p_obj[i].len;

    return sum;
}


static void mibeacon_timer_handler(void * p_context)
{
    uint32_t errno;
    uint8_t len;
    mibeacon_frame_ctrl_t fctrl = {
#if defined(ENABLE_REPLAY_PROTECT) && (ENABLE_REPLAY_PROTECT)
            .version        = 5,
#else
            .version        = 4,
#endif
    };

    mibeacon_capability_t cap = {
            .connectable = 1,
            .encryptable = 1,
            .bondAbility = 1
    };

    mible_addr_t dev_mac;
    mible_gap_address_get(dev_mac);

    mibeacon_config_t beacon_cfg = {
        .frame_ctrl     = fctrl,
        .pid            = beacon_nonce.pid,
        .p_mac          = &dev_mac,
    };

    mibeacon_obj_t obj = {0};
    errno = dequeue(&mi_obj_queue, &obj);

    uint8_t adv_data[31] = {2, 1, 6};
    uint8_t adv_dlen     = 3;

    if (errno != MI_SUCCESS) {
        flags.is_sending = false;

        if (flags.stop_adv_after_sent_out) {
            mible_gap_adv_stop();
            MI_LOG_INFO("stop adv obj.\n");
        }

        beacon_cfg.p_capability = &cap;
        mible_service_data_set(&beacon_cfg, adv_data + 3, &len);
        adv_dlen += len;

        mible_gap_adv_data_set(adv_data, adv_dlen, adv_data, 0);

        MI_LOG_INFO("no more mibeacon obj.\n");
    } else {
        mible_timer_start(mibeacon_timer, OBJ_ADV_TIMEOUT_MS, NULL);

        // encode adv packet.
        if (obj.need_encrypt) {
            beacon_cfg.frame_ctrl.is_encrypt = 1;
            beacon_cfg.p_mac = obj.len > 3 ? NULL : &dev_mac;
        } else if (obj.len > 9) {
            beacon_cfg.p_mac = NULL;
        }
        beacon_cfg.p_obj        = &obj;
        beacon_cfg.obj_num      = 1;
        errno = mible_service_data_set(&beacon_cfg, adv_data + 3, &len);
        if (errno != MI_SUCCESS) {
            MI_LOG_ERROR("%s MI_ERR_DATA_SIZE\n", __func__);
            return;
        }
        adv_dlen += len;

        // encode scan response packet.
        uint8_t scan_rsp_data[31];
        uint8_t scan_rsp_dlen = 0;
        if (beacon_cfg.p_mac == NULL) {
            beacon_cfg.frame_ctrl.is_encrypt = 0;
            beacon_cfg.p_mac        = &dev_mac;
            beacon_cfg.p_capability = &cap;
            mible_manu_data_set(&beacon_cfg, scan_rsp_data, &scan_rsp_dlen);
        }

        errno = mible_gap_adv_data_set(adv_data, adv_dlen, scan_rsp_data, scan_rsp_dlen);
        MI_ERR_CHECK(errno);

        MI_LOG_INFO("send mibeacon obj 0x%04X\n", obj.type);
    }
}


void set_beacon_key(uint8_t *p_key)
{
    if (p_key == NULL) {
        flags.is_valid_key = 0;
    } else {
        mible_gap_address_get(beacon_nonce.mac);
        beacon_nonce.pid = PRODUCT_ID;
        memcpy(beacon_key, p_key, sizeof(beacon_key));
        flags.is_valid_key = 1;
    }

    if (flags.is_init) {
        seqnum.value = 0;
        mible_record_write(REC_ID_SEQNUM, seqnum.byte, 4);
    }
}

mible_status_t mibeacon_init(uint8_t *key)
{
    static mibeacon_obj_t obj_buf[OBJ_QUEUE_SIZE];
    mible_status_t errno;

    errno = queue_init(&mi_obj_queue, (void*) obj_buf, ARRAY_SIZE(obj_buf), sizeof(obj_buf[0]));
    MI_ERR_CHECK(errno);

    if (mibeacon_timer == NULL)
        mible_timer_create(&mibeacon_timer, mibeacon_timer_handler, MIBLE_TIMER_SINGLE_SHOT);

    set_beacon_key(key);

    if (key != NULL &&
        mible_record_read(REC_ID_SEQNUM, seqnum.byte, 4) == MI_SUCCESS) {
        seqnum.value += 512;
        errno = mible_record_write(REC_ID_SEQNUM, seqnum.byte, 4);
        MI_ERR_CHECK(errno);
    }

    MI_LOG_DEBUG("init mibeacon with SEQNUM: %d\n", seqnum.value);

    flags.is_init = 1;
    return errno;
}


mible_status_t mibeacon_data_set(mibeacon_config_t const * const config,
        uint8_t *output, uint8_t *output_len)
{
    mibeacon_frame_ctrl_t * const p_frame_ctrl = (void*)output;
    uint32_t errno = 0;

    if (config == NULL || output == NULL || output_len == NULL) {
        return MI_ERR_INVALID_PARAM;
    }

    /*  encode frame_ctrl and product_id */
    memcpy(output, (uint8_t*)config, 4);
    output[0]   = 0;
    output     += 4;

    /*  encode frame cnt */
    if (++seqnum.value % 512 == 0)
        mible_record_write(REC_ID_SEQNUM, seqnum.byte, 4);
    *output++ = (uint8_t) seqnum.value;

    /*  encode gap mac */
    if (config->p_mac != NULL) {
        p_frame_ctrl->mac_include = 1;
        memcpy(output, config->p_mac, 6);
        output += 6;
    }

    /*  encode capability */
    if (config->p_capability != NULL) {
        p_frame_ctrl->cap_include = 1;
        mibeacon_capability_t *p_cap = (void*)output;
        output += 1;
        *p_cap = *config->p_capability;

        /*  encode WIFI MAC address */
        if (config->p_wifi_mac != NULL) {
            p_cap->bondAbility = 3;
            memcpy(output, config->p_wifi_mac, 2);
            output += 2;
        }

        /*  encode IO cap */
        if (config->p_cap_sub_IO != NULL) {
            p_cap->IO_capability = 1;
            memcpy(output, config->p_cap_sub_IO, sizeof(mibeacon_cap_sub_io_t));
            output += sizeof(mibeacon_cap_sub_io_t);
        }
    }

    /*  encode encrypted objects */
    if (config->p_obj != NULL) {
        if (!flags.is_valid_key)
            return MI_ERR_INVALID_STATE;

        uint8_t *objs_ptr = output;
        uint8_t  objs_len = calc_objs_bytes(config->p_obj, config->obj_num);
        // 7 = 3 bytes ext frame cnt + 4 bytes MIC
        CHECK_ADV_LEN(output - (uint8_t*)p_frame_ctrl + objs_len + 7);

        // append plain objects
        p_frame_ctrl->obj_include = 1;
        for (uint8_t i = 0, max = config->obj_num; i < max; i++) {
            event_encode(config->p_obj + i, output);
            // 3 = 2 bytes object ID + 1 byte length
            output += 3 + config->p_obj[i].len;
        }

        // append ext frame cnt
        beacon_nonce.cnt = seqnum.byte[0];
        memcpy(beacon_nonce.ext_cnt, &seqnum.byte[1], 3);
        memcpy(output, beacon_nonce.ext_cnt, 3);
        output += sizeof(beacon_nonce.ext_cnt);

        // encrypt the objects
        p_frame_ctrl->is_encrypt  = 1;
        uint8_t mic[4];
        uint8_t aad = 0x11;
        errno = aes_ccm_encrypt_and_tag(beacon_key,
                    (uint8_t*)&beacon_nonce, sizeof(beacon_nonce),
                                       &aad, sizeof(aad),
                                   objs_ptr, objs_len,
                                   objs_ptr,
                                        mic, 4);
        MI_ERR_CHECK(errno);
        if (errno)
            return MI_ERR_INTERNAL;

        // append MIC
        memcpy(output, mic, sizeof(mic));
        output += sizeof(mic);
    } else {
        p_frame_ctrl->is_encrypt  = 0;
        p_frame_ctrl->obj_include = 0;
    }

    /*  encode mesh info */
    if (config->p_mesh != NULL) {
        CHECK_ADV_LEN(output - (uint8_t*)p_frame_ctrl + sizeof(mibeacon_mesh_t));
        p_frame_ctrl->mesh = 1;
        memcpy(output, config->p_mesh, sizeof(mibeacon_mesh_t));
        output += sizeof(mibeacon_mesh_t);
    }

    *output_len = output - (uint8_t*)p_frame_ctrl;

    return MI_SUCCESS;
}

mible_status_t fastpair_data_set(mibeacon_config_t const * const config,
        uint8_t *output, uint8_t *output_len)
{
    mibeacon_frame_ctrl_t * const p_frame_ctrl = (void*)(output + 4);
    //uint32_t errno = 0;

    if (config == NULL || output == NULL || output_len == NULL) {
        MI_LOG_ERROR("error parameters.\n");
        return MI_ERR_INVALID_PARAM;
    }

    output[1] = 0x16;
    output[2] = LO_BYTE(BLE_UUID_MI_SERVICE);
    output[3] = HI_BYTE(BLE_UUID_MI_SERVICE);
    output     += 4;
		
    /*  encode frame_ctrl and product_id */
    memcpy(output, (uint8_t*)config, 4);
    output[0]   = 0;
    output     += 4;

    /*  encode frame cnt */
    if (++seqnum.value % 512 == 0)
        mible_record_write(REC_ID_SEQNUM, seqnum.byte, 4);
    *output++ = (uint8_t) seqnum.value;

    /*  encode gap mac */
    if (config->p_mac != NULL) {
        p_frame_ctrl->mac_include = 1;
        memcpy(output, config->p_mac, 6);
        output += 6;
    }

    /*  encode capability */
    if (config->p_capability != NULL) {
        p_frame_ctrl->cap_include = 1;
        mibeacon_capability_t *p_cap = (void*)output;
        output += 1;
        *p_cap = *config->p_capability;

        /*  encode WIFI MAC address */
        if (config->p_wifi_mac != NULL) {
            p_cap->bondAbility = 3;
            memcpy(output, config->p_wifi_mac, 2);
            output += 2;
        }

        /*  encode IO cap */
        if (config->p_cap_sub_IO != NULL) {
            p_cap->IO_capability = 1;
            memcpy(output, config->p_cap_sub_IO, sizeof(mibeacon_cap_sub_io_t));
            output += sizeof(mibeacon_cap_sub_io_t);
        }
    }

    /*  encode uncrypted objects */
    if (config->p_obj != NULL) {

        //uint8_t *objs_ptr = output;
        uint8_t  objs_len = calc_objs_bytes(config->p_obj, config->obj_num);
        // 7 = 3 bytes ext frame cnt + 4 bytes MIC
        CHECK_ADV_LEN(output - (uint8_t*)p_frame_ctrl + objs_len);

        if(MI_EVT_SIMPLE_PAIR != config->p_obj->type){
            MI_LOG_ERROR("Error type.\n");
            return MI_ERR_INVALID_PARAM;
        }
				
        // append plain objects
        p_frame_ctrl->obj_include = 1;
        for (uint8_t i = 0, max = config->obj_num; i < max; i++) {
            event_encode(config->p_obj + i, output);
            // 3 = 2 bytes object ID + 1 byte length
            output += 3 + config->p_obj[i].len;
        }
				
    } else {
        p_frame_ctrl->is_encrypt  = 0;
        p_frame_ctrl->obj_include = 0;
        MI_LOG_ERROR("no object.\n");
        return MI_ERR_INVALID_PARAM;
    }

    /*  encode mesh info */
    if (config->p_mesh != NULL) {
        CHECK_ADV_LEN(output - (uint8_t*)p_frame_ctrl + sizeof(mibeacon_mesh_t));
        p_frame_ctrl->mesh = 1;
        memcpy(output, config->p_mesh, sizeof(mibeacon_mesh_t));
        output += sizeof(mibeacon_mesh_t);
    }
		
    *output_len = output - (uint8_t*)p_frame_ctrl + 4;
    *((uint8_t*)p_frame_ctrl - 4) = *output_len - 1;
		
    return MI_SUCCESS;
}


mible_status_t mible_service_data_set(mibeacon_config_t const * const config,
        uint8_t *p_output, uint8_t *p_output_len)
{
    uint32_t errno;
    uint8_t data_len = 0;

// check input
    if(config == NULL || p_output == NULL || p_output_len == NULL){
        MI_LOG_ERROR("error parameters.\n");
        return MI_ERR_INVALID_PARAM;
    }

    p_output[1] = 0x16;
    p_output[2] = LO_BYTE(BLE_UUID_MI_SERVICE);
    p_output[3] = HI_BYTE(BLE_UUID_MI_SERVICE);
    errno = mibeacon_data_set(config, &p_output[4], &data_len);
    p_output[0] = 3 + data_len;

    if (errno != MI_SUCCESS) {
        MI_ERR_CHECK(errno);
        return MI_ERR_DATA_SIZE;
    }
    
    *p_output_len = 4 + data_len;

    return MI_SUCCESS;
}


mible_status_t mible_manu_data_set(mibeacon_config_t const * const config,
        uint8_t *p_output, uint8_t *p_output_len)
{
    uint32_t errno;
    uint8_t data_len = 0;
// check input
    if(config == NULL || p_output == NULL || p_output_len == NULL){
        MI_LOG_ERROR("error parameters.\n");
        return MI_ERR_INVALID_PARAM;
    }

    p_output[1] = 0xFF;
    p_output[2] = LO_BYTE(BLE_UUID_COMPANY_ID_XIAOMI);
    p_output[3] = HI_BYTE(BLE_UUID_COMPANY_ID_XIAOMI);
    errno = mibeacon_data_set(config, &p_output[4], &data_len);
    p_output[0] = 3 + data_len;
    
    if (errno != MI_SUCCESS) {
        MI_ERR_CHECK(errno);
        return MI_ERR_DATA_SIZE;
    }

    *p_output_len = 4 + data_len;

    return MI_SUCCESS;
}


int mibeacon_obj_enque(mibeacon_obj_name_t nm, uint8_t len, void *val)
{
    uint32_t errno;
    mibeacon_obj_t obj;

    if (!flags.is_valid_key)
        return MI_ERR_INVALID_STATE;

    if (len > sizeof(obj.val))
        return MI_ERR_DATA_SIZE;

    obj.type = nm;
    obj.len  = len;
    obj.need_encrypt = 1;
    memcpy(obj.val, (uint8_t*)val, len);

    errno = enqueue(&mi_obj_queue, &obj);
    if(errno != MI_SUCCESS) {
        MI_LOG_ERROR("push beacon event errno %d\n", errno);
        return MI_ERR_RESOURCES;
    }

    flags.stop_adv_after_sent_out = 0;

    if (flags.is_sending != true ) {
        /* All event will be processed in mibeacon_timer_handler() */
        errno = mible_timer_start(mibeacon_timer, 10, NULL);
        MI_ERR_CHECK(errno);
        if (errno != MI_SUCCESS)
            return MI_ERR_INTERNAL;
        else
            flags.is_sending = true;
    }

    return MI_SUCCESS;
}


int mibeacon_obj_enque_oneshot(mibeacon_obj_name_t nm, uint8_t len, void *val)
{
    uint32_t errno;
    mibeacon_obj_t obj;

    if (!flags.is_valid_key)
        return MI_ERR_INVALID_STATE;

    if (len > sizeof(obj.val))
        return MI_ERR_DATA_SIZE;

    obj.type = nm;
    obj.len  = len;
    obj.need_encrypt = 1;
    memcpy(obj.val, (uint8_t*)val, len);

    errno = enqueue(&mi_obj_queue, &obj);
    if(errno != MI_SUCCESS) {
        MI_LOG_ERROR("push beacon event errno %d\n", errno);
        return MI_ERR_RESOURCES;
    }

    if (flags.stop_adv_after_sent_out == 0) {
        flags.stop_adv_after_sent_out = 1;
        mible_gap_adv_stop();
    }

    if (flags.is_sending != true) {
        mible_gap_adv_param_t param = {
                .adv_interval_max = MSEC_TO_UNITS(OBJ_ADV_INTERVAL_MS, 625),
                .adv_interval_min = MSEC_TO_UNITS(OBJ_ADV_INTERVAL_MS, 625),
                .adv_type = MIBLE_ADV_TYPE_CONNECTABLE_UNDIRECTED
        };

        mible_gap_adv_start(&param);

        /* All event will be processed in mibeacon_timer_handler() */
        errno = mible_timer_start(mibeacon_timer, 10, NULL);
        MI_ERR_CHECK(errno);
        if (errno != MI_SUCCESS)
            return MI_ERR_INTERNAL;
        else
            flags.is_sending = true;
    }

    return MI_SUCCESS;
}
