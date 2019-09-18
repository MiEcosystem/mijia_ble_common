#ifndef MIBLE_BEACON_H__
#define MIBLE_BEACON_H__

#include "mible_api.h"
#include "mible_log.h"
#include "mible_port.h"
#include "mible_type.h"

#define MIBLE_MAX_ADV_LENGTH                        31

typedef struct {
    uint8_t         reserved0           :1;
    uint8_t         reserved1           :1;
    uint8_t         reserved2           :1;
    uint8_t         is_encrypt          :1;
    uint8_t         mac_include         :1;
    uint8_t         cap_include         :1;
    uint8_t         obj_include         :1;
    uint8_t         mesh                :1;

    uint8_t         registered          :1;
    uint8_t         bond_confirm        :1;
    uint8_t         auth_mode           :2;
    uint8_t         version             :4;
} mibeacon_frame_ctrl_t;


typedef enum {
    MI_EVT_BASE          = 0x0000,
    MI_EVT_CONNECT       = 0x0001,
    MI_EVT_SIMPLE_PAIR   = 0x0002,
    MI_EVT_DOOR          = 0x0007,
    MI_EVT_LOCK          = 0x000B,

    MI_STA_BASE         = 0x1000,
    MI_STA_BUTTON       = 0x1001,
    MI_STA_SLEEP        = 0x1002,
    MI_STA_RSSI         = 0x1003,
    MI_STA_TEMPERATURE  = 0x1004,
    MI_STA_WATER_BOIL   = 0x1005,
    MI_STA_HUMIDITY     = 0x1006,
    MI_STA_LUMINA       = 0x1007,
    MI_STA_SOIL_PF      = 0x1008,
    MI_STA_SOIL_EC      = 0x1009,
    MI_STA_BATTERY      = 0x100A,
    MI_STA_LOCK         = 0x100E,
    MI_STA_DOOR         = 0x100F,

} mibeacon_obj_name_t;
typedef struct {
    uint16_t        type;
    uint8_t         len;
    uint8_t         need_encrypt;
    uint8_t         val[12];
 } mibeacon_obj_t;

typedef struct {
    uint8_t         connectable  :1;
    uint8_t         centralable  :1;
    uint8_t         encryptable  :1;
    uint8_t         bondAbility  :2;
    uint8_t         IO_capability:1;
    uint8_t         reserved     :2;
} mibeacon_capability_t;

typedef struct {
    uint8_t in_digits            :1;
    uint8_t in_alphabet          :1;
    uint8_t in_nfc_tag           :1;
    uint8_t in_image             :1;
    uint8_t out_digits           :1;
    uint8_t out_alphabet         :1;
    uint8_t out_nfc_tag          :1;
    uint8_t out_image            :1;
    uint8_t reserved             :8;
} mibeacon_cap_sub_io_t;

typedef struct {
    uint8_t         pb_adv       :1;
    uint8_t         pb_gatt      :1;
    uint8_t         state        :2;
    uint8_t         version      :4;
    uint8_t         reserved     :8;
} mibeacon_mesh_t;

typedef struct {
    mibeacon_frame_ctrl_t   frame_ctrl;
    uint16_t                pid;
    mible_addr_t           *p_mac;
    mibeacon_capability_t  *p_capability;
    mibeacon_cap_sub_io_t  *p_cap_sub_IO;
    uint8_t 			   *p_wifi_mac;
    mibeacon_obj_t         *p_obj;
    uint8_t                 obj_num;
    mibeacon_mesh_t        *p_mesh;
} mibeacon_config_t;

void set_beacon_key(uint8_t *p_key);

mible_status_t mibeacon_init(uint8_t *key);

/*
 * @brief   set mibeacon service data
 * @param   [in] config: mibeacon configure data
 *          [out] p_output: pointer to mibeacon data  (watch out array out of bounds)
 *          [out] p_output_len: pointer to mibeacon data length
 * @return  MI_ERR_INVALID_PARAM:   Invalid pointer supplied or mismatched frame_ctrl.
 *          MI_ERR_INVALID_LENGTH:  Adv data length exceeds MIBLE_MAX_ADV_LENGTH-7.
 *          MI_ERR_INTERNAL:        Not found rand num used to encrypt data.
 *          MI_SUCCESS:             Set successfully.
 * */
mible_status_t mibeacon_data_set(mibeacon_config_t const * const config,
        uint8_t *p_output, uint8_t *p_output_len);

mible_status_t fastpair_data_set(mibeacon_config_t const * const config,
        uint8_t *p_output, uint8_t *p_output_len);
/*
 * @brief   Set <service data>.
 * @param   [in] config: mibeacon configure data
 *          [out] p_output: pointer to mibeacon data  (watch out array out of bounds)
 *          [out] p_output_len: pointer to mibeacon data length
 * @return  MI_ERR_INVALID_PARAM:   Invalid pointer supplied.
 *          MI_SUCCESS:             Set successfully.
 *          MI_ERR_DATA_SIZE:       Adv bytes excceed the maximun.
 * */
mible_status_t mible_service_data_set(mibeacon_config_t const * const config,
        uint8_t *p_output, uint8_t *p_output_len);

/*
 * @brief   Set <manufacturer> data.
 * @param   [in] config: mibeacon configure data
 *          [out] p_output: pointer to mibeacon data  (watch out array out of bounds)
 *          [out] p_output_len: pointer to mibeacon data length
 * @return  MI_ERR_INVALID_PARAM:   Invalid pointer supplied.
 *          MI_ERR_INVALID_LENGTH:  Data length exceeds MIBLE_MAX_ADV_LENGTH.
 *          MI_SUCCESS:             Set successfully.
 * @Note:   p_obj[obj_num-1]
 * */
mible_status_t mible_manu_data_set(mibeacon_config_t const * const config,
        uint8_t *p_output, uint8_t *p_output_len);

/**
 * @brief   Enqueue a object value into the mibeacon object queue.
 *
 * @param   [in] nm:  object id name
 *          [in] len: length of the object value
 *          [in] val: pointer to the object value
 *
 * @return  MI_SUCCESS             Successfully enqueued a object into the object queue.
 *          MI_ERR_DATA_SIZE       Object value length is too long.
 *          MI_ERR_RESOURCES       Object queue is full. Please try again later.
 *          MI_ERR_INTERNAL        Can not invoke the sending handler.
 *
 * @note    This function ONLY works when the device has been registered and has restored the keys.
 *
 * The mibeacon object is an adv message contains the status or event. BLE gateway
 * can receive the beacon message (by BLE scanning) and upload it to server for
 * triggering customized home automation scene.
 *
 * OBJ_QUEUE_SIZE      : max num of objects can be concurrency advertising
 *                      ( actually, it will be sent one by one )
 * OBJ_ADV_INTERVAL    : the object adv interval
 * OBJ_ADV_TIMEOUT_MS  : the time one object will be continuously sent.
 *
 * */
int mibeacon_obj_enque(mibeacon_obj_name_t nm, uint8_t len, void *val);

/**
 * @brief   Enqueue a object value into the mibeacon object queue.
 * When the object queue is sent out, it will turn off BLE advertising.
 *
 * @param   [in] nm:  object id name
 *          [in] len: length of the object value
 *          [in] val: pointer to the object value
 *
 * @return  MI_SUCCESS             Successfully enqueued a object into the object queue.
 *          MI_ERR_DATA_SIZE       Object value length is too long.
 *          MI_ERR_RESOURCES       Object queue is full. Please try again later.
 *          MI_ERR_INTERNAL        Can not invoke the sending handler.
 *
 * @note    This function ONLY works when the device has been registered and has restored the keys.
 *
 * The mibeacon object is an adv message contains the status or event. BLE gateway
 * can receive the beacon message (by BLE scanning) and upload it to server for
 * triggering customized home automation scene.
 *
 * OBJ_QUEUE_SIZE      : max num of objects can be concurrency advertising
 *                      ( actually, it will be sent one by one )
 * OBJ_ADV_INTERVAL    : the object adv interval
 * OBJ_ADV_TIMEOUT_MS  : the time one object will be continuously sent.
 *
 * */
int mibeacon_obj_enque_oneshot(mibeacon_obj_name_t nm, uint8_t len, void *val);

#endif
