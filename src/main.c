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

#include "cbor.h"
#include "os.h"
#include "cx.h"
#include "blake2.h"
#include "blake2-impl.h"

#include "os_io_seproxyhal.h"
#include <string.h>
#include <stdbool.h>

unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_address_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_address_cancel(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_preview_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_preview_cancel(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_preview_prev(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_preview_next(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_sign_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_sign_cancel(const bagl_element_t *e);

unsigned int prepare_tx_preview_ui();

//TODO: Remove - Temp
unsigned int io_seproxyhal_touch_show_preview(const bagl_element_t *e);

#define MAX_BIP32_PATH 10
#define MAX_USER_NAME 20
#define MAX_CHUNK_SIZE 55
#define MAX_MSG 1023

#define ADA_COIN_TYPE 0x717
#define ADA_ADDR_PATH_LEN 0x05
#define ADA_WALLET_PATH_LEN 0x03
#define BIP_44 0x2C
#define HARDENED_BIP32 0x80000000

#define CLA 0x80
#define INS_GET_PUBLIC_KEY 0x02
#define INS_HASH 0x04
#define INS_SIGN_TX 0x06
#define INS_GET_RND_PUB_KEY 0x0C
#define INS_GET_WALLET_INDEX 0x0E
#define P1_FIRST 0x01
#define P1_NEXT 0x02
#define P2_CURVE25519 0x02
#define P2_RANDOM_INDEX 0x04
#define P2_PASSED_IN_INDEX 0x06
#define P2_SINGLE_TX 0x01
#define P2_MULTI_TX 0x02

#define OFFSET_CLA 0
#define OFFSET_INS 1
#define OFFSET_P1 2
#define OFFSET_P2 3
#define OFFSET_LC 4
#define OFFSET_CDATA 5

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

ux_state_t ux;

// display stepped screens
unsigned int ux_step;
unsigned int ux_step_count;

typedef struct operationContext_t {
    uint8_t pathLength;
    uint32_t bip32Path[MAX_BIP32_PATH];
    cx_ecfp_public_key_t publicKey;
    cx_curve_t curve;
    cx_sha256_t hash;
    unsigned char chainCode[32];
    bool direct;
    bool fullMessageHash;
    bool getPublicKey;
    bool usePassedInIndex;
    uint8_t hashData[32];
    uint8_t userName[MAX_USER_NAME + 1]; // TODO: Remove
    uint8_t message[MAX_MSG];
    uint32_t messageLength;
    uint64_t transactionLength;
    uint32_t transactionOffset;
    uint8_t finalUTXOCount;
    uint32_t addressData[32];
    uint64_t txAmountData[32];
    uint8_t hashTX[32];
    uint8_t outputTxCount;
} operationContext_t;

char ui_send_ada_to_label[] = "Send ADA";
char ui_send_to_address_label[] = "To Address";
char ui_tx_fee_label[] = "TX Fee ADA";

char * ui_strings[4];

struct {
    char ui_label[32];
    char ui_value[32];
    uint8_t tx_ui_step;
    uint8_t otx_count;
} tx;

char keyPath[200];
operationContext_t operationContext;






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
                                  unsigned int button_mask_counter) {
    switch (button_mask) {

        case BUTTON_EVT_RELEASED | BUTTON_LEFT: // EXIT

            // TODO: Wipe TX and all data
            io_seproxyhal_touch_exit(NULL);

            break;

        case BUTTON_EVT_RELEASED | BUTTON_RIGHT: // APPORVE

            io_seproxyhal_touch_show_preview(NULL);

            break;
    }
    return 0;
}



const bagl_element_t bagl_ui_sign_tx_nanos[] = {
    // {
    //     {type, userid, x, y, width, height, stroke, radius, fill, fgcolor,
    //      bgcolor, font_id, icon_id},
    //     text,
    //     touch_area_brim,
    //     overfgcolor,
    //     overbgcolor,
    //     tap,
    //     out,
    //     over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000,
         0xFFFFFF, 0, 0},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_LABELINE, 0x00, 0, 12, 128, 16, 0, 0, 0, 0xFFFFFF, 0x000000,
         BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
        "Sign",
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_LABELINE, 0x00, 0, 28, 128, 16, 0, 0, 0, 0xFFFFFF, 0x000000,
         BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
        "Transaction?",
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_ICON, 0x00, 0, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
         BAGL_GLYPH_ICON_CROSS},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_ICON, 0x00, 120, 12, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
         BAGL_GLYPH_ICON_CHECK},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
};

unsigned int
bagl_ui_sign_tx_nanos_button(unsigned int button_mask,
                            unsigned int button_mask_counter) {
    switch (button_mask) {

        case BUTTON_EVT_RELEASED | BUTTON_LEFT: // EXIT

            io_seproxyhal_touch_sign_cancel(NULL);

            break;

        case BUTTON_EVT_RELEASED | BUTTON_RIGHT: // APPORVE

            io_seproxyhal_touch_sign_ok(NULL);

            break;
    }
    return 0;
}





const bagl_element_t bagl_ui_preview_tx_nanos[] = {
    // {
    //     {type, userid, x, y, width, height, stroke, radius, fill, fgcolor,
    //      bgcolor, font_id, icon_id},
    //     text,
    //     touch_area_brim,
    //     overfgcolor,
    //     overbgcolor,
    //     tap,
    //     out,
    //     over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000,
         0xFFFFFF, 0, 0},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_LABELINE, 0x00, 0, 12, 128, 16, 0, 0, 0, 0xFFFFFF, 0x000000,
         BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
        tx.ui_label,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_LABELINE, 0x00, 0, 28, 128, 16, 0, 0, 0, 0xFFFFFF, 0x000000,
         BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
        tx.ui_value,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_ICON, 0x00, 0, 4, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
         BAGL_GLYPH_ICON_LEFT},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_ICON, 0x00, 120, 4, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
         BAGL_GLYPH_ICON_RIGHT},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
};

unsigned int
bagl_ui_preview_tx_nanos_button(unsigned int button_mask,
                            unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:

        io_seproxyhal_touch_preview_prev(NULL);

        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:

        io_seproxyhal_touch_preview_next(NULL);

        break;
    }
    return 0;
}


const bagl_element_t bagl_ui_approval_preview_tx_nanos[] = {
    // {
    //     {type, userid, x, y, width, height, stroke, radius, fill, fgcolor,
    //      bgcolor, font_id, icon_id},
    //     text,
    //     touch_area_brim,
    //     overfgcolor,
    //     overbgcolor,
    //     tap,
    //     out,
    //     over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000,
         0xFFFFFF, 0, 0},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_LABELINE, 0x00, 0, 12, 128, 16, 0, 0, 0, 0xFFFFFF, 0x000000,
         BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
        "Preview",
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_LABELINE, 0x00, 0, 28, 128, 16, 0, 0, 0, 0xFFFFFF, 0x000000,
         BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
        "Transaction?",
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_ICON, 0x00, 0, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
         BAGL_GLYPH_ICON_CROSS},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_ICON, 0x00, 120, 12, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
         BAGL_GLYPH_ICON_CHECK},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
};

unsigned int
bagl_ui_approval_preview_tx_nanos_button(unsigned int button_mask,
                            unsigned int button_mask_counter) {
    switch (button_mask) {

        case BUTTON_EVT_RELEASED | BUTTON_LEFT: // EXIT

            io_seproxyhal_touch_sign_cancel(NULL);

            break;

        case BUTTON_EVT_RELEASED | BUTTON_RIGHT: // APPORVE PREVIEW

            io_seproxyhal_touch_preview_ok(NULL);

            break;
    }
    return 0;
}








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



void ui_idle(void) {
    if (os_seph_features() &
        SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_SCREEN_BIG) {
        // Ledger Blue not supported
        THROW(0x600C);
    } else {
        UX_DISPLAY(ui_idle_nanos, NULL);
    }
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

void parse_cbor_transaction() {

  cbor_stream_t stream;
  cbor_init(&stream, operationContext.message, operationContext.transactionLength);

  uint8_t array_length;
  //uint32_t int_value;
  //bool at_tag = false;
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
      error = true;
      THROW(0x6DDB);
  }

  // Scan through Output TXs
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

              // Trying to work with uint64_t again
              operationContext.txAmountData[otx_count-1] =
                       ((uint64_t)txAmount[7]) | ((uint64_t)txAmount[6] << 8) |
                       ((uint64_t)txAmount[5] << 16) | ((uint64_t)txAmount[4] << 24) |
                       ((uint64_t)txAmount[3] << 32) | ((uint64_t)txAmount[2] << 40) |
                       ((uint64_t)txAmount[1] << 48) | ((uint64_t)txAmount[0] << 56);

              /*
              uint8_t txAmountIndex = (otx_count - 1) * 2;
              operationContext.txAmountData[txAmountIndex] =
                  (txAmount[3] << 24) | (txAmount[2] << 16) |
                  (txAmount[1] << 8) | (txAmount[0]);
              operationContext.txAmountData[txAmountIndex + 1] =
                  (txAmount[7] << 24) | (txAmount[6] << 16) |
                  (txAmount[5] << 8) | (txAmount[4]);
              */
              offset += 8;
          } else {
              error = true;
              THROW(0x6DDC);
          }
          operationContext.outputTxCount = otx_count;
      }
  } else {
      // Invalid TX, must have at least one output
      error = true;
      THROW(0x6DDD);
  }

  operationContext.finalUTXOCount = otx_count;
  cbor_destroy(&stream);

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

bool adjustDecimals(char *src, uint32_t srcLength, char *target,
                    uint32_t targetLength, uint8_t decimals) {
    uint32_t startOffset;
    uint32_t lastZeroOffset = 0;
    uint32_t offset = 0;

    if ((srcLength == 1) && (*src == '0')) {
        if (targetLength < 2) {
            return false;
        }
        target[offset++] = '0';
        target[offset++] = '\0';
        return true;
    }
    if (srcLength <= decimals) {
        uint32_t delta = decimals - srcLength;
        if (targetLength < srcLength + 1 + 2 + delta) {
            return false;
        }
        target[offset++] = '0';
        target[offset++] = '.';
        for (uint32_t i = 0; i < delta; i++) {
            target[offset++] = '0';
        }
        startOffset = offset;
        for (uint32_t i = 0; i < srcLength; i++) {
            target[offset++] = src[i];
        }
        target[offset] = '\0';
    } else {
        uint32_t sourceOffset = 0;
        uint32_t delta = srcLength - decimals;
        if (targetLength < srcLength + 1 + 1) {
            return false;
        }
        while (offset < delta) {
            target[offset++] = src[sourceOffset++];
        }
        if (decimals != 0) {
            target[offset++] = '.';
        }
        startOffset = offset;
        while (sourceOffset < srcLength) {
            target[offset++] = src[sourceOffset++];
        }
        target[offset] = '\0';
    }
    for (uint32_t i = startOffset; i < offset; i++) {
        if (target[i] == '0') {
            if (lastZeroOffset == 0) {
                lastZeroOffset = i;
            }
        } else {
            lastZeroOffset = 0;
        }
    }
    if (lastZeroOffset != 0) {
        target[lastZeroOffset] = '\0';
        if (target[lastZeroOffset - 1] == '.') {
            target[lastZeroOffset - 1] = '\0';
        }
    }
    return true;
}

unsigned short ada_print_amount(uint64_t amount, char *out,
                                uint32_t outlen) {
    char tmp[20];
    char tmp2[25];
    uint32_t numDigits = 0, i;
    uint64_t base = 1;
    while (base <= amount) {
        base *= 10;
        numDigits++;
    }
    if (numDigits > sizeof(tmp) - 1) {
        THROW(EXCEPTION);
    }
    base /= 10;
    for (i = 0; i < numDigits; i++) {
        tmp[i] = '0' + ((amount / base) % 10);
        base /= 10;
    }
    tmp[i] = '\0';
    //strcpy(tmp2, "");
    adjustDecimals(tmp, i, tmp2 + 4, 25, 6);
    if (strlen(tmp2) < outlen - 1) {
        strcpy(out, tmp2);
    } else {
        out[0] = '\0';
    }
    return strlen(out);
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

/* TODO: Remove
unsigned int ui_idle_nanos_button(unsigned int button_mask,
                                  unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // EXIT
        io_seproxyhal_touch_exit(NULL);
        break;
    }
    return 0;
}
*/

unsigned int io_seproxyhal_touch_show_preview(const bagl_element_t *e) {
    UX_DISPLAY(bagl_ui_approval_preview_tx_nanos, NULL);
    return 0;
}

unsigned int io_seproxyhal_touch_preview_ok(const bagl_element_t *e) {
    tx.tx_ui_step = 0;
    tx.otx_count = operationContext.finalUTXOCount;

    prepare_tx_preview_ui();

    UX_DISPLAY(bagl_ui_preview_tx_nanos, NULL);

    //snprintf(tx.ui_label, 65, "%.*H", 32, tx.ui_label);

    return 0;
}

unsigned int io_seproxyhal_touch_preview_cancel(const bagl_element_t *e) {
    tx.tx_ui_step = -1;
    // TODO: Wipe TX and all data
    ui_idle();

    return 0;
}

unsigned int io_seproxyhal_touch_preview_prev(const bagl_element_t *e) {
    if(tx.tx_ui_step > 0) {  // GO BACK

        tx.tx_ui_step--;

    } else { // EXIT

        UX_DISPLAY(bagl_ui_approval_preview_tx_nanos, NULL);
        return 0;
    }

    prepare_tx_preview_ui();

    UX_DISPLAY(bagl_ui_preview_tx_nanos, NULL);

    return 0;
}

unsigned int io_seproxyhal_touch_preview_next(const bagl_element_t *e) {

    if(tx.tx_ui_step == (tx.otx_count * 2)) {  // CONTINUE TO SIGN
        UX_DISPLAY(bagl_ui_sign_tx_nanos, NULL);
        return 0;
    } else {  // SHOW NEXT
        tx.tx_ui_step++;
    }

    prepare_tx_preview_ui();

    UX_DISPLAY(bagl_ui_preview_tx_nanos, NULL);

    return 0;
}

unsigned int prepare_tx_preview_ui() {

    ui_strings[0] = "Send ADA";
    ui_strings[1] = "To Address";
    ui_strings[2] = "TX Fee ADA";

    uint64_t fee = 0x00000000;

    os_memset(tx.ui_label, 0, 32);
    os_memset(tx.ui_value, 0, 32);

    int tx_amount_index = tx.tx_ui_step/2;
    int tx_address_index = (tx.tx_ui_step -1)/2;

    if(tx.tx_ui_step == (tx.otx_count * 2)) {
        os_memmove(tx.ui_label, ui_strings[2], 32);
        ada_print_amount(fee, tx.ui_value, 32);
    } else if(tx.tx_ui_step % 2 == 0) { // EVEN TX AMOUNT
        os_memmove(tx.ui_label, ui_strings[0], 32);
        ada_print_amount(operationContext.txAmountData[tx_amount_index], tx.ui_value, 32);
    } else {  // ODD TX ADDRESS
        os_memmove(tx.ui_label, ui_strings[1], 32);
        ada_print_amount(operationContext.addressData[tx_address_index], tx.ui_value, 32);
    }

    return 0;
}


unsigned int io_seproxyhal_touch_sign_ok(const bagl_element_t *e) {

    uint32_t tx = 0;
    G_io_apdu_buffer[tx++] = operationContext.finalUTXOCount;
    G_io_apdu_buffer[tx++] = 0xFF;

    for (int i=0; i < operationContext.finalUTXOCount; i++ ) {
        os_memmove(G_io_apdu_buffer + tx,
          &operationContext.addressData[i], 4);
        tx += 4;
        G_io_apdu_buffer[tx++] = 0xFF;

        //Using uint32_t example needs to double index for each address
        //os_memmove(G_io_apdu_buffer + tx, &operationContext.txAmountData[i*2], 8);

        os_memmove(G_io_apdu_buffer + tx, &operationContext.txAmountData[i], 8);
        tx += 8;

        //os_memmove(G_io_apdu_buffer + tx, &operationContext.txAmountData[i+1], 4);
        //tx += 4;

        G_io_apdu_buffer[tx++] = 0xFF;
    }

    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();

    return 0;
}

unsigned int io_seproxyhal_touch_sign_cancel(const bagl_element_t *e) {

    //TODO: Cleanup transaction data

    uint32_t tx = 0;
    G_io_apdu_buffer[tx++] = operationContext.finalUTXOCount;
    G_io_apdu_buffer[tx++] = 0x00;

    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();

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
                        //Blue Not supported
                        THROW(0x600C);
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

                    // Ensure ED25519 Curve is being requested
                    if ((G_io_apdu_buffer[OFFSET_P1] != 0) ||
                        ((G_io_apdu_buffer[OFFSET_P2] != P2_CURVE25519))) {
                        THROW(0x6B00);
                    }

                    // Get BIP32 address being requested
                    for (i = 0; i < operationContext.pathLength; i++) {
                        operationContext.bip32Path[i] =
                            (dataBuffer[0] << 24) | (dataBuffer[1] << 16) |
                            (dataBuffer[2] << 8) | (dataBuffer[3]);
                        dataBuffer += 4;
                    }

                    // Set Curve
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
                        // Ledger Blue not supported
                        THROW(0x600C);
                    } else {
                        UX_DISPLAY(ui_address_nanos, NULL);
                    }
                    flags |= IO_ASYNCH_REPLY;
                }

                break;



                case INS_HASH: {

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

                        if(p2 == P2_MULTI_TX) {
                            dataLength = MAX_CHUNK_SIZE;
                        } else if (p2 != P2_SINGLE_TX) {
                            THROW(0x6B02);
                        }
                        operationContext.transactionOffset = 0;
                        operationContext.fullMessageHash = false;
                    } else if (p1 != P1_NEXT) {
                        THROW(0x6B00);
                    }

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
                        parse_cbor_transaction();
                        int error = blake2b( operationContext.hashTX,
                                 32,
                                 operationContext.message,
                                 //testTX,
                                 operationContext.transactionLength,
                                 //20,
                                 NULL,
                                 0 );
                        if(error == 0) {
                            //THROW(0x6BAA);
                        } else if (error == -1) {
                            THROW(0x6BBB);
                        } else if (error == -2) {
                            THROW(0x6BCC);
                        } else if (error == -3) {
                            THROW(0x6BDD);
                        } else if (error == -4) {
                            THROW(0x6BEE);
                        } else {
                            THROW(0x6BFF);
                        }

                    }

                    uint32_t tx = 0;
                    if(operationContext.fullMessageHash) {
                        G_io_apdu_buffer[tx++] = 0x20;
                        //os_memmove(G_io_apdu_buffer + tx, &operationContext.transactionLength, 8);
                        //tx += 8;
                        os_memmove(G_io_apdu_buffer + tx, &operationContext.hashTX, 32);
                        tx += 32;
                    }

                    G_io_apdu_buffer[tx++] = 0x90;
                    G_io_apdu_buffer[tx++] = 0x00;
                    // Send back the response, do not restart the event loop
                    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
                    // Display back the original UX
                    ui_idle();
                }

                break;










                case INS_SIGN_TX: {

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
                        if(p2 == P2_MULTI_TX) {
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
                        parse_cbor_transaction();
                    }



                    if(operationContext.fullMessageHash) {

                        UX_DISPLAY(bagl_ui_approval_preview_tx_nanos, NULL);
                        flags |= IO_ASYNCH_REPLY;

                    } else {
                        uint32_t tx = 0;
                        G_io_apdu_buffer[tx++] = 0x90;
                        G_io_apdu_buffer[tx++] = 0x00;
                        // Send back the response, do not restart the event loop
                        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
                        // Display back the original UX
                        ui_idle();
                    }
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
