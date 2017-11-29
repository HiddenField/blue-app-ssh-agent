/*******************************************************************************
*   Ledger Blue
*   (c) 2016 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include <cbor.h>
#include "os.h"
#include "cx.h"
#include <stdbool.h>

#include "os_io_seproxyhal.h"
#include "string.h"

unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_sign_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_sign_cancel(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_address_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_address_cancel(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_ecdh_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_ecdh_cancel(const bagl_element_t *e);

#define MAX_BIP32_PATH 10
#define MAX_USER_NAME 20
#define MAX_CHUNK_SIZE 55

#define ADA_COIN_TYPE 0x717
#define ADA_ADDR_PATH_LEN 0x05
#define ADA_WALLET_PATH_LEN 0x03
#define BIP_44 0x2C
#define HARDENED_BIP32 0x80000000

#define CLA 0x80
#define INS_GET_PUBLIC_KEY 0x02
#define INS_SIGN_SSH_BLOB 0x04
#define INS_SIGN_TX 0x06
#define INS_SIGN_DIRECT_HASH 0x08
#define INS_GET_ECDH_SECRET 0x0A
#define INS_GET_RND_PUB_KEY 0x0C
#define INS_GET_WALLET_INDEX 0x0E
#define P1_FIRST 0x01
#define P1_NEXT 0x02
#define P1_LAST_MARKER 0x80
#define P2_PRIME256 0x01
#define P2_CURVE25519 0x02
#define P2_RANDOM_INDEX 0x04
#define P2_PASSED_IN_INDEX 0x06
#define P2_PUBLIC_KEY_MARKER 0x80
#define P2_SINGLE_TX 0x01
#define P2_MULTI_TX 0x02

#define OFFSET_CLA 0
#define OFFSET_INS 1
#define OFFSET_P1 2
#define OFFSET_P2 3
#define OFFSET_LC 4
#define OFFSET_CDATA 5

#define DEPTH_REQUEST_1 0
#define DEPTH_REQUEST_2 3
#define DEPTH_USER 1
#define DEPTH_LAST 6

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

ux_state_t ux;

// display stepped screens
unsigned int ux_step;
unsigned int ux_step_count;

#define MAX_MSG 1023

typedef struct operationContext_t {
    uint8_t pathLength;
    uint32_t bip32Path[MAX_BIP32_PATH];
    cx_sha256_t hash;
    cx_ecfp_public_key_t publicKey;
    cx_curve_t curve;
    unsigned char chainCode[32];
    uint8_t depth;
    bool readingElement;
    bool direct;
    bool fullMessageHash;
    bool getPublicKey;
    bool usePassedInIndex;
    uint8_t hashData[32];
    uint8_t lengthBuffer[4];
    uint8_t lengthOffset;
    uint32_t elementLength;
    uint8_t userName[MAX_USER_NAME + 1];
    uint32_t userOffset;
    uint8_t message[MAX_MSG];
    uint32_t messageLength;
    uint32_t transactionLength;
    uint32_t transactionOffset;
    uint8_t finalUTXOCount;
    uint32_t addressData[32];
    uint32_t txAmountData[64];
} operationContext_t;

char keyPath[200];
operationContext_t operationContext;

bagl_element_t const ui_address_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 60, 320, 420, 0, 0, BAGL_FILL, 0xf9f9f9,
      0xf9f9f9, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    // type                                 id    x    y    w    h    s  r  fill
    // fg        bg        font icon   text, out, over, touch
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 60, 0, 0, BAGL_FILL, 0x1d2028, 0x1d2028,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 20, 0, 320, 60, 0, 0, BAGL_FILL, 0xFFFFFF, 0x1d2028,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
     "Cardano ADA",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 35, 385, 120, 40, 0, 6,
      BAGL_FILL, 0xcccccc, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CANCEL",
     0,
     0x37ae99,
     0xF9F9F9,
     io_seproxyhal_touch_address_cancel,
     NULL,
     NULL},
    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 165, 385, 120, 40, 0, 6,
      BAGL_FILL, 0x41ccb4, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CONFIRM",
     0,
     0x37ae99,
     0xF9F9F9,
     io_seproxyhal_touch_address_ok,
     NULL,
     NULL},

    {{BAGL_LABEL, 0x00, 0, 147, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Get public key for path",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 0, 280, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_16px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL}};

unsigned int ui_address_blue_button(unsigned int button_mask,
                                    unsigned int button_mask_counter) {
    return 0;
}

// UI to approve or deny the signature proposal
static const bagl_element_t const ui_approval_ssh_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 60, 320, 420, 0, 0, BAGL_FILL, 0xf9f9f9,
      0xf9f9f9, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    // type                                 id    x    y    w    h    s  r  fill
    // fg        bg        font icon   text, out, over, touch
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 60, 0, 0, BAGL_FILL, 0x1d2028, 0x1d2028,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 20, 0, 320, 60, 0, 0, BAGL_FILL, 0xFFFFFF, 0x1d2028,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
     "Cardano ADA",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 35, 385, 120, 40, 0, 6,
      BAGL_FILL, 0xcccccc, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CANCEL",
     0,
     0x37ae99,
     0xF9F9F9,
     io_seproxyhal_touch_sign_cancel,
     NULL,
     NULL},
    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 165, 385, 120, 40, 0, 6,
      BAGL_FILL, 0x41ccb4, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CONFIRM",
     0,
     0x37ae99,
     0xF9F9F9,
     io_seproxyhal_touch_sign_ok,
     NULL,
     NULL},

    {{BAGL_LABEL, 0x00, 0, 87, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm SSH authentication with key",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 0, 125, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_16px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

unsigned int ui_approval_ssh_blue_button(unsigned int button_mask,
                                         unsigned int button_mask_counter) {
    return 0;
}

// UI to approve or deny the signature proposal
static const bagl_element_t const ui_approval_pgp_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 60, 320, 420, 0, 0, BAGL_FILL, 0xf9f9f9,
      0xf9f9f9, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    // type                                 id    x    y    w    h    s  r  fill
    // fg        bg        font icon   text, out, over, touch
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 60, 0, 0, BAGL_FILL, 0x1d2028, 0x1d2028,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 20, 0, 320, 60, 0, 0, BAGL_FILL, 0xFFFFFF, 0x1d2028,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
     "Cardano ADA",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 35, 385, 120, 40, 0, 6,
      BAGL_FILL, 0xcccccc, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CANCEL",
     0,
     0x37ae99,
     0xF9F9F9,
     io_seproxyhal_touch_sign_cancel,
     NULL,
     NULL},
    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 165, 385, 120, 40, 0, 6,
      BAGL_FILL, 0x41ccb4, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CONFIRM",
     0,
     0x37ae99,
     0xF9F9F9,
     io_seproxyhal_touch_sign_ok,
     NULL,
     NULL},

    {{BAGL_LABEL, 0x00, 0, 87, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm PGP import with key",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 0, 125, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_16px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

unsigned int ui_approval_pgp_blue_button(unsigned int button_mask,
                                         unsigned int button_mask_counter) {
    return 0;
}

// UI to approve or deny the signature proposal
static const bagl_element_t const ui_approval_pgp_ecdh_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 60, 320, 420, 0, 0, BAGL_FILL, 0xf9f9f9,
      0xf9f9f9, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    // type                                 id    x    y    w    h    s  r  fill
    // fg        bg        font icon   text, out, over, touch
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 60, 0, 0, BAGL_FILL, 0x1d2028, 0x1d2028,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 20, 0, 320, 60, 0, 0, BAGL_FILL, 0xFFFFFF, 0x1d2028,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
     "Cardano ADA",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 35, 385, 120, 40, 0, 6,
      BAGL_FILL, 0xcccccc, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CANCEL",
     0,
     0x37ae99,
     0xF9F9F9,
     io_seproxyhal_touch_ecdh_cancel,
     NULL,
     NULL},
    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 165, 385, 120, 40, 0, 6,
      BAGL_FILL, 0x41ccb4, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CONFIRM",
     0,
     0x37ae99,
     0xF9F9F9,
     io_seproxyhal_touch_ecdh_ok,
     NULL,
     NULL},

    {{BAGL_LABEL, 0x00, 0, 87, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm PGP ECDH with key",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 0, 125, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_16px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

unsigned int
ui_approval_pgp_ecdh_blue_button(unsigned int button_mask,
                                 unsigned int button_mask_counter) {
    return 0;
}

// UI displayed when no signature proposal has been received
static const bagl_element_t const ui_idle_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 60, 320, 420, 0, 0, BAGL_FILL, 0xf9f9f9,
      0xf9f9f9, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 60, 0, 0, BAGL_FILL, 0x1d2028, 0x1d2028,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABEL, 0x00, 20, 0, 320, 60, 0, 0, BAGL_FILL, 0xFFFFFF, 0x1d2028,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
     "Cardano ADA",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 190, 215, 120, 40, 0, 6,
      BAGL_FILL, 0x41ccb4, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "Exit",
     0,
     0x37ae99,
     0xF9F9F9,
     io_seproxyhal_touch_exit,
     NULL,
     NULL}

};

unsigned int ui_idle_blue_button(unsigned int button_mask,
                                 unsigned int button_mask_counter) {
    return 0;
}

const bagl_element_t ui_idle_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Cardano ADA",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    //{{BAGL_LABELINE                       , 0x02,   0,  26, 128,  32, 0, 0, 0
    //, 0xFFFFFF, 0x000000,
    //BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  },
    //"Waiting for requests...", 0, 0, 0, NULL, NULL, NULL },

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};
unsigned int ui_idle_nanos_button(unsigned int button_mask,
                                  unsigned int button_mask_counter);

const bagl_element_t ui_address_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x01, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Cardano ADA",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Provide public key?",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};
unsigned int ui_address_nanos_button(unsigned int button_mask,
                                     unsigned int button_mask_counter);

const bagl_element_t ui_approval_ssh_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x01, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Cardano ADA",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Authenticate?",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "User",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (char *)operationContext.userName,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};
unsigned int ui_approval_ssh_nanos_button(unsigned int button_mask,
                                          unsigned int button_mask_counter);

const bagl_element_t ui_approval_pgp_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x01, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Cardano ADA",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Sign?",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};
unsigned int ui_approval_pgp_nanos_button(unsigned int button_mask,
                                          unsigned int button_mask_counter);

const bagl_element_t ui_approval_pgp_ecdh_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x01, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Cardano ADA",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "ECDH?",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};
unsigned int
ui_approval_pgp_ecdh_nanos_button(unsigned int button_mask,
                                  unsigned int button_mask_counter);

void ui_idle(void) {
    if (os_seph_features() &
        SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_SCREEN_BIG) {
        UX_DISPLAY(ui_idle_blue, NULL);
    } else {
        UX_DISPLAY(ui_idle_nanos, NULL);
    }
}

unsigned int ui_approval_ssh_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        switch (element->component.userid) {
        case 1:
            io_seproxyhal_setup_ticker(2000);
            break;
        case 2:
            io_seproxyhal_setup_ticker(3000);
            break;
        }
        return (ux_step == element->component.userid - 1);
    }
    return 1;
}

uint32_t path_item_to_string(char *dest, uint32_t number) {
    uint32_t offset = 0;
    uint32_t startOffset = 0, destOffset = 0;
    uint8_t i;
    uint8_t tmp[11];
    bool hardened = ((number & 0x80000000) != 0);
    number &= 0x7FFFFFFF;
    uint32_t divIndex = 0x3b9aca00;
    while (divIndex != 0) {
        tmp[offset++] = '0' + ((number / divIndex) % 10);
        divIndex /= 10;
    }
    tmp[offset] = '\0';
    while ((tmp[startOffset] == '0') && (startOffset < offset)) {
        startOffset++;
    }
    if (startOffset == offset) {
        dest[destOffset++] = '0';
    } else {
        for (i = startOffset; i < offset; i++) {
            dest[destOffset++] = tmp[i];
        }
    }
    if (hardened) {
        dest[destOffset++] = '\'';
    }
    dest[destOffset++] = '\0';
    return destOffset;
}

uint32_t path_to_string(char *dest) {
    uint8_t i;
    uint32_t offset = 0;
    for (i = 0; i < operationContext.pathLength; i++) {
        uint32_t length =
            path_item_to_string(dest + offset, operationContext.bip32Path[i]);
        offset += length;
        offset--;
        if (i != operationContext.pathLength - 1) {
            dest[offset++] = '/';
        }
    }
    dest[offset++] = '\0';
    return offset;
}

uint32_t generate_random_hardened_index() {

    uint32_t random_hardened_index = 0;

    uint8_t tmp[4];
    cx_rng(tmp, 4);
    random_hardened_index = 0x80000000 |
                        (tmp[0] << 24) |
                        (tmp[1] << 16) |
                        (tmp[2] << 8) |
                         tmp[3];

    return random_hardened_index;
}

void derive_bip32_node_private_key(uint8_t *privateKeyData) {

  // START Node Derivation
  #if CX_APILEVEL >= 5
      os_perso_derive_node_bip32(
          CX_CURVE_Ed25519,
          operationContext.bip32Path,
          operationContext.pathLength,
          privateKeyData,
          operationContext.chainCode);
  #else
      os_perso_derive_seed_bip32(operationContext.bip32Path,
                                 operationContext.pathLength,
                                 privateKeyData,
                                 operationContext.chainCode);
  #endif
  // END Node Derivation

}

unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e) {
    // Go back to the dashboard
    os_sched_exit(0);
    return 0; // do not redraw the widget
}

unsigned int ui_idle_nanos_button(unsigned int button_mask,
                                  unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // EXIT
        io_seproxyhal_touch_exit(NULL);
        break;
    }
    return 0;
}

unsigned int io_seproxyhal_touch_sign_ok(const bagl_element_t *e) {
    uint8_t privateKeyData[32];
    uint8_t hash[32];
    cx_ecfp_private_key_t privateKey;
    uint32_t tx = 0;
    if (!operationContext.direct) {
        if (!operationContext.fullMessageHash) {
            cx_hash(&operationContext.hash.header, CX_LAST, hash, 0, hash);
        }
    } else {
        os_memmove(hash, operationContext.hashData, 32);
    }
#if CX_APILEVEL >= 5
    os_perso_derive_node_bip32(
        operationContext.curve, operationContext.bip32Path,
        operationContext.pathLength, privateKeyData, NULL);
#else
    os_perso_derive_seed_bip32(operationContext.bip32Path,
                               operationContext.pathLength, privateKeyData,
                               NULL);
#endif
    cx_ecfp_init_private_key(operationContext.curve, privateKeyData, 32,
                             &privateKey);
    os_memset(privateKeyData, 0, sizeof(privateKeyData));
    if (operationContext.curve == CX_CURVE_Ed25519) {
        if (!operationContext.fullMessageHash) {
            tx = cx_eddsa_sign(&privateKey, NULL, CX_LAST, CX_SHA512, hash,
                               sizeof(hash), G_io_apdu_buffer);
        } else {
            tx = cx_eddsa_sign(
                &privateKey, NULL, CX_LAST, CX_SHA512, operationContext.message,
                operationContext.messageLength, G_io_apdu_buffer);
        }
    } else {
        tx = cx_ecdsa_sign(&privateKey, CX_RND_RFC6979 | CX_LAST, CX_SHA256,
                           hash, sizeof(hash), G_io_apdu_buffer);
    }
    if (operationContext.getPublicKey) {
#if ((CX_APILEVEL >= 5) && (CX_APILEVEL < 7))
        if (operationContext.curve == CX_CURVE_Ed25519) {
            cx_ecfp_init_public_key(operationContext.curve, NULL, 0,
                                    &operationContext.publicKey);
            cx_eddsa_get_public_key(&privateKey, &operationContext.publicKey);
        } else {
            cx_ecfp_generate_pair(operationContext.curve,
                                  &operationContext.publicKey, &privateKey, 1);
        }
#else
        cx_ecfp_generate_pair(operationContext.curve,
                              &operationContext.publicKey, &privateKey, 1);
#endif
        os_memmove(G_io_apdu_buffer + tx, operationContext.publicKey.W, 65);
        tx += 65;
    }
    os_memset(&privateKey, 0, sizeof(privateKey));
    os_memset(&privateKeyData, 0, sizeof(privateKeyData));
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_sign_cancel(const bagl_element_t *e) {
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_ecdh_ok(const bagl_element_t *e) {
    uint8_t privateKeyData[32];
    cx_ecfp_private_key_t privateKey;
    uint32_t tx = 0;
#if CX_APILEVEL >= 5
    os_perso_derive_node_bip32(
        operationContext.curve, operationContext.bip32Path,
        operationContext.pathLength, privateKeyData, NULL);
#else
    os_perso_derive_seed_bip32(operationContext.bip32Path,
                               operationContext.pathLength, privateKeyData,
                               NULL);
#endif
    cx_ecfp_init_private_key(operationContext.curve, privateKeyData, 32,
                             &privateKey);
    tx = cx_ecdh(&privateKey, CX_ECDH_POINT, operationContext.publicKey.W,
                 G_io_apdu_buffer);
    os_memset(&privateKey, 0, sizeof(privateKey));
    os_memset(&privateKeyData, 0, sizeof(privateKeyData));
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_ecdh_cancel(const bagl_element_t *e) {
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int ui_approval_ssh_nanos_button(unsigned int button_mask,
                                          unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // CANCEL
        io_seproxyhal_touch_sign_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: { // OK
        io_seproxyhal_touch_sign_ok(NULL);
        break;
    }
    }
    return 0;
}

unsigned int ui_approval_pgp_nanos_button(unsigned int button_mask,
                                          unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // CANCEL
        io_seproxyhal_touch_sign_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: { // OK
        io_seproxyhal_touch_sign_ok(NULL);
        break;
    }
    }
    return 0;
}

unsigned int
ui_approval_pgp_ecdh_nanos_button(unsigned int button_mask,
                                  unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // CANCEL
        io_seproxyhal_touch_ecdh_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: { // OK
        io_seproxyhal_touch_ecdh_ok(NULL);
        break;
    }
    }
    return 0;
}

unsigned int io_seproxyhal_touch_address_ok(const bagl_element_t *e) {
    uint32_t tx = 0;
    G_io_apdu_buffer[tx++] = 65; // + sizeof(operationContext.chainCode);
    os_memmove(G_io_apdu_buffer + tx, operationContext.publicKey.W, 65);
    tx += 65;

    // output chain code
    os_memmove(G_io_apdu_buffer + tx,
               operationContext.chainCode,
               sizeof(operationContext.chainCode));
    tx += sizeof(operationContext.chainCode);


    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_address_cancel(const bagl_element_t *e) {
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int ui_address_nanos_button(unsigned int button_mask,
                                     unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // CANCEL
        io_seproxyhal_touch_address_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: { // OK
        io_seproxyhal_touch_address_ok(NULL);
        break;
    }
    }
    return 0;
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
    case CHANNEL_KEYBOARD:
        break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
        if (tx_len) {
            io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

            if (channel & IO_RESET_AFTER_REPLIED) {
                reset();
            }
            return 0; // nothing received from the master so far (it's a tx
                      // transaction)
        } else {
            return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                          sizeof(G_io_apdu_buffer), 0);
        }

    default:
        THROW(INVALID_PARAMETER);
    }
    return 0;
}


void sample_main(void) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        volatile unsigned short sw = 0;

        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0; // ensure no race in catch_other if io_exchange throws
                        // an error
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

                // no apdu received, well, reset the session, and reset the
                // bootloader configuration
                if (rx == 0) {
                    THROW(0x6982);
                }

                if (G_io_apdu_buffer[0] != CLA) {
                    THROW(0x6E00);
                }

                switch (G_io_apdu_buffer[1]) {

                case INS_GET_WALLET_INDEX: {
                    uint8_t privateKeyData[32];
                    uint32_t i;

                    operationContext.pathLength = ADA_WALLET_PATH_LEN;

                    operationContext.bip32Path[0] = BIP_44 | HARDENED_BIP32;
                    operationContext.bip32Path[1] = ADA_COIN_TYPE |
                                                    HARDENED_BIP32;

                    for (i = 0; i < HARDENED_BIP32; i++) {

                      operationContext.bip32Path[2] = i | HARDENED_BIP32;

                      derive_bip32_node_private_key(privateKeyData);

                      if(privateKeyData[31] == 0) {
                          break;
                      }
                    }

                    uint32_t tx = 0;
                    G_io_apdu_buffer[tx++] = 4;
                    os_memmove(G_io_apdu_buffer + tx, &i, 4);
                    tx += 4;
                    G_io_apdu_buffer[tx++] = 0x90;
                    G_io_apdu_buffer[tx++] = 0x00;
                    // Send back the response, do not restart the event loop
                    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
                    // Display back the original UX
                    ui_idle();
                }

                break;

                case INS_GET_RND_PUB_KEY: {
                    uint8_t privateKeyData[32];
                    cx_ecfp_private_key_t privateKey;
                    uint8_t *dataBuffer = G_io_apdu_buffer + OFFSET_CDATA + 1;

                    // Ada addresses are at a fixed depth of 5. Using the
                    // input apdu length field to determine if an address index
                    // has been passed in.
                    operationContext.pathLength =
                        G_io_apdu_buffer[OFFSET_CDATA];
                    if (operationContext.pathLength == 0x00) {
                        operationContext.usePassedInIndex = false;
                    } else {
                        operationContext.usePassedInIndex = true;
                    }

                    if ((G_io_apdu_buffer[OFFSET_P1] != 0) ||
                        (G_io_apdu_buffer[OFFSET_P2] != P2_CURVE25519)) {
                        THROW(0x6B00);
                    }

                    operationContext.pathLength = ADA_ADDR_PATH_LEN;

                    operationContext.bip32Path[0] = BIP_44 | HARDENED_BIP32;
                    operationContext.bip32Path[1] = ADA_COIN_TYPE |
                                                    HARDENED_BIP32;
                    /*
                    //TODO: Call and store Wallet_Index based on Cardano scheme
                    // for deducing what a valid index is, as this is not
                    // normally 0.
                    //
                    // Path Depth 2 == Wallet Index
                    */
                    operationContext.bip32Path[2] = 0 | HARDENED_BIP32;
                    // Path Depth 3 == Account Index - Hardcoded at 0 currently
                    operationContext.bip32Path[3] = 0 | HARDENED_BIP32;

                    if(operationContext.usePassedInIndex) {
                        operationContext.bip32Path[4] =
                           (dataBuffer[0] << 24) | (dataBuffer[1] << 16) |
                           (dataBuffer[2] << 8) | (dataBuffer[3]);
                    } else {
                        operationContext.bip32Path[4] =
                        generate_random_hardened_index();
                    }

                    derive_bip32_node_private_key(privateKeyData);

                    cx_ecfp_init_private_key(CX_CURVE_Ed25519,
                                              privateKeyData, 32,
                                              &privateKey);
#if ((CX_APILEVEL >= 5) && (CX_APILEVEL < 7))

                    cx_ecfp_init_public_key(CX_CURVE_Ed25519, NULL, 0,
                                                &operationContext.publicKey);
                    cx_eddsa_get_public_key(&privateKey,
                                                &operationContext.publicKey);
#else
                    cx_ecfp_generate_pair(CX_CURVE_Ed25519,
                                          &operationContext.publicKey,
                                          &privateKey, 1);
#endif
                    os_memset(&privateKey, 0, sizeof(privateKey));
                    os_memset(privateKeyData, 0, sizeof(privateKeyData));
                    path_to_string(keyPath);
                    if (os_seph_features() &
                        SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_SCREEN_BIG) {
                        UX_DISPLAY(ui_address_blue, NULL);
                    } else {
                        UX_DISPLAY(ui_address_nanos, NULL);
                    }
                    flags |= IO_ASYNCH_REPLY;
                }

                break;

                case INS_GET_PUBLIC_KEY: {
                    uint8_t privateKeyData[32];
                    uint32_t i;
                    uint8_t *dataBuffer = G_io_apdu_buffer + OFFSET_CDATA + 1;
                    cx_ecfp_private_key_t privateKey;
                    cx_curve_t curve;

                    operationContext.pathLength =
                        G_io_apdu_buffer[OFFSET_CDATA];
                    if ((operationContext.pathLength < 0x01) ||
                        (operationContext.pathLength > MAX_BIP32_PATH)) {
                        screen_printf("Invalid path\n");
                        THROW(0x6a80);
                    }

                    if ((G_io_apdu_buffer[OFFSET_P1] != 0) ||
                        ((G_io_apdu_buffer[OFFSET_P2] != P2_PRIME256) &&
                         (G_io_apdu_buffer[OFFSET_P2] != P2_CURVE25519))) {
                        THROW(0x6B00);
                    }
                    for (i = 0; i < operationContext.pathLength; i++) {
                        operationContext.bip32Path[i] =
                            (dataBuffer[0] << 24) | (dataBuffer[1] << 16) |
                            (dataBuffer[2] << 8) | (dataBuffer[3]);
                        dataBuffer += 4;
                    }

                    if (G_io_apdu_buffer[OFFSET_P2] == P2_PRIME256) {
                        curve = CX_CURVE_256R1;
                    } else {
#if 0
                        normalize_curve25519(privateKeyData);
#endif
                        curve = CX_CURVE_Ed25519;
                    }

                    curve = CX_CURVE_Ed25519;
                    derive_bip32_node_private_key(privateKeyData);
                    cx_ecfp_init_private_key(curve, privateKeyData, 32,
                                             &privateKey);

#if ((CX_APILEVEL >= 5) && (CX_APILEVEL < 7))
                    if (curve == CX_CURVE_Ed25519) {
                        cx_ecfp_init_public_key(curve, NULL, 0,
                                                &operationContext.publicKey);
                        cx_eddsa_get_public_key(&privateKey,
                                                &operationContext.publicKey);
                    } else {
                        cx_ecfp_generate_pair(
                            curve, &operationContext.publicKey, &privateKey, 1);
                    }
#else
                    cx_ecfp_generate_pair(curve, &operationContext.publicKey,
                                          &privateKey, 1);
#endif

                    os_memset(&privateKey, 0, sizeof(privateKey));
                    os_memset(privateKeyData, 0, sizeof(privateKeyData));
                    path_to_string(keyPath);
                    if (os_seph_features() &
                        SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_SCREEN_BIG) {
                        UX_DISPLAY(ui_address_blue, NULL);
                    } else {
                        UX_DISPLAY(ui_address_nanos, NULL);
                    }
                    flags |= IO_ASYNCH_REPLY;
                }

                break;

                case INS_SIGN_TX: {

                    uint8_t addr_checksum_tmp[4];
                    uint32_t addr_checksum;
                    uint8_t tx_amount_tmp[8];
                    uint32_t tx_amount_1;
                    uint32_t tx_amount_2;

                    uint8_t p1 = G_io_apdu_buffer[OFFSET_P1];
                    uint8_t p2 = G_io_apdu_buffer[OFFSET_P2];
                    uint8_t *dataBuffer = G_io_apdu_buffer + OFFSET_CDATA;
                    uint32_t dataLength =
                        (G_io_apdu_buffer[5] << 24) | (G_io_apdu_buffer[6] << 16) |
                        (G_io_apdu_buffer[7] << 8) | (G_io_apdu_buffer[8]);
                    dataBuffer += 4;

                    // First APDU -
                    if (p1 == P1_FIRST) {
                        // First APDU contains total transaction length
                        operationContext.transactionLength = dataLength;
                        /*
                        if(operationContext.messageLength != 314) {
                            THROW(0x6B01);
                        }
                        */
                        if(p2 = P2_MULTI_TX) {
                            dataLength = MAX_CHUNK_SIZE;
                        } else if (p2 != P2_SINGLE_TX) {
                            THROW(0x6B02);
                        }
                        operationContext.transactionOffset = 0;
                        operationContext.fullMessageHash = false;
                    } else if (p1 != P1_NEXT) {
                        THROW(0x6B00);
                    }

                    //dataBuffer = G_io_apdu_buffer + OFFSET_LC + 4;

                    os_memmove(operationContext.message +
                                operationContext.transactionOffset,
                               dataBuffer, dataLength);

                    operationContext.transactionOffset += dataLength;

                    if(operationContext.transactionOffset ==
                      operationContext.transactionLength
                    ) {
                        operationContext.fullMessageHash = true;
                    }


                    if(operationContext.fullMessageHash) {
                        cbor_stream_t stream;
                        cbor_init(&stream, operationContext.message, dataLength);

                        uint8_t array_length;
                        uint32_t int_value;
                        bool at_tag = false;
                        bool error = false;
                        uint8_t itx_count = 0;
                        uint8_t otx_count = 0;

                        uint32_t offset = cbor_deserialize_array(&stream, 0, &array_length);
                        if(offset != 1) { THROW(0x6DDE); }

                        // Scan through Input TX and ensure they're valid
                        if(cbor_deserialize_array_indefinite(&stream, offset) ) {
                            offset++;
                            while(!cbor_at_break(&stream, offset) && !error) {
                                itx_count++;
                                // TODO: These methods are returning 0 on the
                                // Ledger. Work out why...
                                //offset += cbor_deserialize_array(&stream, offset, &array_length);
                                //offset += cbor_deserialize_int(&stream, offset, &int_value);
                                // Skip tag
                                offset += 4;
                                if(operationContext.message[offset] == 0x58) {
                                    array_length = operationContext.message[++offset];
                                    //THROW(0xAA00 | array_length);
                                    // Skip Array Length
                                    offset += (array_length + 1);
                                } else {
                                    // TODO: Must throw here
                                    error = true;

                                    if(itx_count != 1) {
                                        THROW(0x6E00 | operationContext.message[offset]);
                                    }
                                    THROW(0x6DDA);
                                }
                            }
                            offset++;
                        } else {
                            // Invalid TX, must have at least one input
                            // TODO: Must throw here
                            error = true;
                            THROW(0x6DDB);
                        }

                        // Scan through Output TXs
                        size_t int_size;
                        //int64_t addr_checksum;
                        int new_offset = cbor_deserialize_array_indefinite(&stream, offset);

                        if(cbor_deserialize_array_indefinite(&stream, offset) ) {
                            offset ++;

                            while(!cbor_at_break(&stream, offset) && !error) {
                                otx_count++;
                                // TODO: These methods are returning 0 on the
                                // Ledger. Work out why...
                                //offset += cbor_deserialize_array(&stream, offset, &array_length);
                                //offset += cbor_deserialize_array(&stream, offset, &array_length);
                                // Skip tag
                                offset += 4;
                                if(operationContext.message[offset] == 0x58) {
                                    array_length = operationContext.message[++offset];
                                    // Skip Array Length
                                    offset += array_length +1;
                                    // TODO: These methods are returning 0 on the
                                    // Ledger. Work out why...
                                    //offset += cbor_deserialize_int64_t(&stream, offset, &addr_checksum);
                                    // Skip CBOR int type
                                    offset++;
                                    uint8_t *checkSum = operationContext.message + offset;
                                    operationContext.addressData[otx_count-1] =
                                        (checkSum[3] << 24) | (checkSum[2] << 16) |
                                        (checkSum[1] << 8) | (checkSum[0]);
                                    offset += 4;
                                    //offset += cbor_deserialize_int64_t(&stream, offset, &addr_checksum);
                                    // Skip CBOR int type
                                    offset++;
                                    uint8_t *txAmount = operationContext.message + offset;
                                    uint8_t txAmountIndex = (otx_count - 1) * 2;
                                    operationContext.txAmountData[txAmountIndex] =
                                        (txAmount[3] << 24) | (txAmount[2] << 16) |
                                        (txAmount[1] << 8) | (txAmount[0]);
                                    operationContext.txAmountData[txAmountIndex + 1] =
                                        (txAmount[7] << 24) | (txAmount[6] << 16) |
                                        (txAmount[5] << 8) | (txAmount[4]);
                                    offset += 8;
                                } else {
                                    // TODO: Must throw here
                                    error = true;
                                    THROW(0x6DDC);
                                }
                            }
                        } else {
                            // Invalid TX, must have at least one output
                            // TODO: Must throw here
                            error = true;
                            THROW(0x6DDD);
                        }

                        operationContext.finalUTXOCount = otx_count;
                        cbor_destroy(&stream);
                    }

                    uint32_t tx = 0;

                    if(operationContext.fullMessageHash) {

                        G_io_apdu_buffer[tx++] = &operationContext.finalUTXOCount;
                        G_io_apdu_buffer[tx++] = 0xFF;

                        for (int i=0; i < operationContext.finalUTXOCount; i++ ) {
                          os_memmove(G_io_apdu_buffer + tx,
                            &operationContext.addressData[i], 4);
                          tx += 4;
                          G_io_apdu_buffer[tx++] = 0xFF;
                          os_memmove(G_io_apdu_buffer + tx, &operationContext.txAmountData[i*2], 8);
                          tx += 8;
                          //os_memmove(G_io_apdu_buffer + tx, &operationContext.txAmountData[i+1], 4);
                          //tx += 4;
                          G_io_apdu_buffer[tx++] = 0xFF;
                        }
                        //os_memmove(G_io_apdu_buffer + tx, &operationContext.transactionLength, 4);
                        //tx += 4;
                        //os_memmove(G_io_apdu_buffer + tx, &dataLength, 4);
                        //tx += 4;
                        //os_memmove(G_io_apdu_buffer + tx, &operationContext.transactionOffset, 4);
                        //tx += 4;
                        //os_memmove(G_io_apdu_buffer + tx, operationContext.message, 200);
                        //tx += 200;
                    }
                    G_io_apdu_buffer[tx++] = 0x90;
                    G_io_apdu_buffer[tx++] = 0x00;
                    // Send back the response, do not restart the event loop
                    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
                    // Display back the original UX
                    ui_idle();
                }

                break;

                case 0xFF: // return to dashboard
                    os_sched_exit(0);

                default:
                    THROW(0x6D00);
                    break;
                }
            }
            CATCH_OTHER(e) {
                switch (e & 0xF000) {
                case 0x6000:
                case 0x9000:
                    sw = e;
                    break;
                default:
                    sw = 0x6800 | (e & 0x7FF);
                    break;
                }
                // Unexpected exception => report
                G_io_apdu_buffer[tx] = sw >> 8;
                G_io_apdu_buffer[tx + 1] = sw;
                tx += 2;
            }
            FINALLY {
            }
        }
        END_TRY;
    }
}

void io_seproxyhal_display(const bagl_element_t *element) {
    return io_seproxyhal_display_default((bagl_element_t *)element);
}

unsigned char io_event(unsigned char channel) {
    // nothing done with the event, throw an error on the transport layer if
    // needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_FINGER_EVENT:
        UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
        break;

#ifdef HAVE_BLE
    // Make automatically discoverable again when disconnected

    case SEPROXYHAL_TAG_BLE_CONNECTION_EVENT:
        if (G_io_seproxyhal_spi_buffer[3] == 0) {
            // TODO : cleaner reset sequence
            // first disable BLE before turning it off
            G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_BLE_RADIO_POWER;
            G_io_seproxyhal_spi_buffer[1] = 0;
            G_io_seproxyhal_spi_buffer[2] = 1;
            G_io_seproxyhal_spi_buffer[3] = 0;
            io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 4);
            // send BLE power on (default parameters)
            G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_BLE_RADIO_POWER;
            G_io_seproxyhal_spi_buffer[1] = 0;
            G_io_seproxyhal_spi_buffer[2] = 1;
            G_io_seproxyhal_spi_buffer[3] = 3; // ble on & advertise
            io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 5);
        }
        break;
#endif

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        UX_DISPLAYED_EVENT({});
        break;

    case SEPROXYHAL_TAG_TICKER_EVENT:
        // prepare next screen
        ux_step = (ux_step + 1) % ux_step_count;
        // redisplay screen
        UX_REDISPLAY();
        break;

    // unknown events are acknowledged
    default:
        break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }
    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

void app_exit(void) {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

__attribute__((section(".boot"))) int main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    UX_INIT();

    // ensure exception will work as planned
    os_boot();

    BEGIN_TRY {
        TRY {
            io_seproxyhal_init();

            USB_power(1);

            ui_idle();

            sample_main();
        }
        CATCH_OTHER(e) {
        }
        FINALLY {
        }
    }
    END_TRY;

    app_exit();
}
