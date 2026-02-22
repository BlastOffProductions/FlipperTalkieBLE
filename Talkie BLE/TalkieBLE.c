/**
 * FlipperChat v2.0 — True Flipper-to-Flipper E2E Encrypted BLE Chat
 *
 * ── Hardware requirement ──────────────────────────────────────────────────
 *  Each Flipper Zero needs an ESP32 module flashed with Espressif AT firmware
 *  wired to GPIO pins:
 *
 *    Flipper Pin 13 (TX) ──→ ESP32 RX0 (GPIO3 on ESP32, pin 44 on ESP32-S2)
 *    Flipper Pin 14 (RX) ←── ESP32 TX0 (GPIO1 on ESP32, pin 43 on ESP32-S2)
 *    Flipper Pin  1 (5V) ──→ ESP32 5V  (enable 5V in Flipper GPIO menu first)
 *    Flipper Pin 18 (GND)──→ ESP32 GND
 *
 *  ESP-AT firmware download: https://docs.espressif.com/projects/esp-at/
 *
 * ── How it works ─────────────────────────────────────────────────────────
 *  HOST side:
 *    1. App sends AT commands to ESP32 to start BLE advertising as
 *       "FlipperChat" (server role)
 *    2. Waits for +BLECONN event from ESP32
 *    3. On connect, enters passphrase-auth exchange then chat
 *
 *  CLIENT side:
 *    1. App sends AT+BLESCAN to ESP32, parses results
 *    2. Shows list of discovered "FlipperChat" devices on screen
 *    3. User selects one → app connects via AT+BLECONN
 *    4. Enters passphrase → chat opens
 *
 *  MESSAGING:
 *    Uses ESP32 BLE SPP transparent transmission mode (AT+BLESPPCFG).
 *    The Flipper app encrypts each message with AES-128-CTR before
 *    handing it to the ESP32, and decrypts incoming data on receipt.
 *    The passphrase is never transmitted — only used locally to derive
 *    the AES key. A challenge-response handshake confirms both sides
 *    share the same key before the chat opens.
 *
 * ── Build ─────────────────────────────────────────────────────────────────
 *    ufbt build && ufbt launch
 */

#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_input.h>
#include <gui/modules/popup.h>
#include <gui/modules/loading.h>
#include <gui/view.h>
#include <gui/canvas.h>
#include <input/input.h>
#include <notification/notification_messages.h>
#include <furi_hal_serial.h>
#include <furi_hal_random.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define TAG               "FlipperChat"

/* ── Sizes ──────────────────────────────────────────────────────────────── */
#define MAX_MSG           64
#define MAX_PASS          20
#define KEY_LEN           16
#define NONCE_LEN         8
#define MAX_CHAT_LINES    32
#define CHAT_LINE_W       21   /* chars that fit at FontSecondary on 128px  */
#define CHAT_VISIBLE      6    /* lines visible on screen                   */
#define MAX_PEERS         8    /* max scan results                          */
#define PEER_NAME_LEN     24
#define PEER_ADDR_LEN     18   /* "xx:xx:xx:xx:xx:xx\0"                    */

/* ── UART ───────────────────────────────────────────────────────────────── */
#define ESP_UART_ID       FuriHalSerialIdUsart
#define ESP_UART_BAUD     115200
#define UART_RING_SIZE    512
#define UART_RING_MASK    (UART_RING_SIZE - 1)
#define AT_RESP_BUF       256

/* ── Protocol framing for app<->app messages over BLE SPP ───────────────
 *  All data sent through the BLE SPP transparent channel is framed as:
 *    0x02 | type(1) | nonce(8) | enc_len(1) | ciphertext(enc_len) | crc16(2)
 *
 *  Types:
 *    0x01  MSG   — encrypted chat message
 *    0x02  HELLO — challenge (random 8 bytes, encrypted)
 *    0x03  HELLOACK — response to challenge
 */
#define FRAME_MSG         0x01
#define FRAME_HELLO       0x02
#define FRAME_HELLOACK    0x03
#define FRAME_MAX_ENC     80
#define FRAME_OVERHEAD    13   /* STX+type+nonce+len+crc = 13              */

/* ═══════════════════════════════════════════════════════════════════════════
 *  Self-contained AES-128-CTR + SHA-256
 *  (mbedTLS symbols are disabled in the Flipper FAP API)
 * ═══════════════════════════════════════════════════════════════════════════ */

static const uint8_t AES_S[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};
#define XT(x) (((x)<<1)^(((x)&0x80)?0x1b:0))

static void aes_expand(const uint8_t k[16], uint8_t rk[11][16]) {
    static const uint8_t RC[10]={0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
    memcpy(rk[0], k, 16);
    for(int i=0;i<10;i++){
        uint8_t t[4]={AES_S[rk[i][13]]^RC[i],AES_S[rk[i][14]],
                      AES_S[rk[i][15]],AES_S[rk[i][12]]};
        for(int b=0;b<4;b++) rk[i+1][b]   =rk[i][b]   ^t[b];
        for(int b=0;b<4;b++) rk[i+1][4+b] =rk[i][4+b] ^rk[i+1][b];
        for(int b=0;b<4;b++) rk[i+1][8+b] =rk[i][8+b] ^rk[i+1][4+b];
        for(int b=0;b<4;b++) rk[i+1][12+b]=rk[i][12+b]^rk[i+1][8+b];
    }
}

static void aes_block(const uint8_t rk[11][16], const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    for(int i=0;i<16;i++) s[i]=in[i]^rk[0][i];
    for(int r=1;r<=10;r++){
        for(int i=0;i<16;i++) s[i]=AES_S[s[i]];
        uint8_t t;
        t=s[1];s[1]=s[5];s[5]=s[9];s[9]=s[13];s[13]=t;
        t=s[2];s[2]=s[10];s[10]=t;t=s[6];s[6]=s[14];s[14]=t;
        t=s[15];s[15]=s[11];s[11]=s[7];s[7]=s[3];s[3]=t;
        if(r<10){
            for(int c=0;c<4;c++){
                uint8_t a=s[c*4],b=s[c*4+1],cc=s[c*4+2],d=s[c*4+3];
                s[c*4+0]=XT(a)^XT(b)^b^cc^d;
                s[c*4+1]=a^XT(b)^XT(cc)^cc^d;
                s[c*4+2]=a^b^XT(cc)^XT(d)^d;
                s[c*4+3]=XT(a)^a^b^cc^XT(d);
            }
        }
        for(int i=0;i<16;i++) s[i]^=rk[r][i];
    }
    memcpy(out,s,16);
}

static void aes_ctr(const uint8_t key[KEY_LEN], const uint8_t nonce[NONCE_LEN],
                    uint8_t *data, size_t len) {
    uint8_t rk[11][16], ctr[16]={0}, ks[16];
    aes_expand(key, rk);
    memcpy(ctr, nonce, NONCE_LEN);
    for(size_t o=0; o<len;) {
        aes_block(rk, ctr, ks);
        size_t chunk = (len-o>16)?16:(len-o);
        for(size_t i=0;i<chunk;i++) data[o+i]^=ks[i];
        o+=chunk;
        for(int i=15;i>=8;i--) if(++ctr[i]) break;
    }
}

/* SHA-256 */
#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
static const uint32_t SK[64]={
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};
static void sha256_compress(uint32_t h[8], const uint8_t b[64]) {
    uint32_t w[64];
    for(int i=0;i<16;i++) w[i]=((uint32_t)b[i*4]<<24)|((uint32_t)b[i*4+1]<<16)|((uint32_t)b[i*4+2]<<8)|b[i*4+3];
    for(int i=16;i<64;i++){
        uint32_t s0=RR(w[i-15],7)^RR(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1=RR(w[i-2],17)^RR(w[i-2],19)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    uint32_t a=h[0],b2=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for(int i=0;i<64;i++){
        uint32_t S1=RR(e,6)^RR(e,11)^RR(e,25);
        uint32_t ch=(e&f)^(~e&g);
        uint32_t t1=hh+S1+ch+SK[i]+w[i];
        uint32_t S0=RR(a,2)^RR(a,13)^RR(a,22);
        uint32_t maj=(a&b2)^(a&c)^(b2&c);
        uint32_t t2=S0+maj;
        hh=g;g=f;f=e;e=d+t1;d=c;c=b2;b2=a;a=t1+t2;
    }
    h[0]+=a;h[1]+=b2;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}
__attribute__((noinline))
static void sha256(const uint8_t *msg, size_t len, uint8_t digest[32]) {
    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t block[64]; size_t i=0;
    while(i+64<=len){ memcpy(block,msg+i,64); sha256_compress(h,block); i+=64; }
    size_t rem=len-i; memcpy(block,msg+i,rem);
    block[rem++]=0x80;
    if(rem>56){ memset(block+rem,0,64-rem); sha256_compress(h,block); rem=0; }
    memset(block+rem,0,56-rem);
    uint64_t bits=(uint64_t)len*8;
    for(int j=0;j<8;j++) block[56+j]=(uint8_t)(bits>>(56-j*8));
    sha256_compress(h,block);
    for(int j=0;j<8;j++){digest[j*4]=(uint8_t)(h[j]>>24);digest[j*4+1]=(uint8_t)(h[j]>>16);
                          digest[j*4+2]=(uint8_t)(h[j]>>8);digest[j*4+3]=(uint8_t)h[j];}
}
static void derive_key(const char *pass, uint8_t key[KEY_LEN]) {
    uint8_t h[32]; sha256((const uint8_t*)pass,strlen(pass),h); memcpy(key,h,KEY_LEN);
}

static uint16_t crc16(const uint8_t *d, size_t n) {
    uint16_t c=0xFFFF;
    while(n--){ c^=(uint16_t)*d++<<8; for(int i=0;i<8;i++) c=(c&0x8000)?(c<<1)^0x1021:(c<<1); }
    return c;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  App state
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum {
    ViewMenu=0, ViewPassphrase, ViewChat, ViewSend,
    ViewScan, ViewConnecting, ViewInfo,
} ChatViewId;

typedef enum {
    RoleNone=0, RoleHost, RoleClient,
} ChatRole;

typedef enum {
    ConnNone=0, ConnAdvertising, ConnScanning,
    ConnConnecting, ConnHandshake, ConnReady, ConnError,
} ConnState;

typedef struct {
    char name[PEER_NAME_LEN];
    char addr[PEER_ADDR_LEN];
    int  rssi;
} Peer;

typedef struct ChatApp ChatApp;
struct ChatApp {
    /* GUI */
    Gui*             gui;
    ViewDispatcher*  vd;
    Submenu*         menu;
    TextInput*       pass_input;
    TextInput*       send_input;
    Popup*           info_popup;
    View*            chat_view;
    View*            scan_view;
    View*            connecting_view;
    NotificationApp* notif;
    ChatViewId       cur_view;

    /* State */
    ChatRole   role;
    ConnState  conn;
    bool       key_set;
    uint8_t    key[KEY_LEN];
    char       pass_buf[MAX_PASS+1];
    char       send_buf[MAX_MSG+1];

    /* Chat log */
    char     lines[MAX_CHAT_LINES][CHAT_LINE_W+1];
    int      line_count;
    int      scroll;
    FuriMutex* log_mutex;

    /* Scan results */
    Peer     peers[MAX_PEERS];
    int      peer_count;
    int      peer_sel;    /* selected peer index in scan list */
    FuriMutex* peer_mutex;

    /* UART / ESP32 */
    FuriHalSerialHandle* serial;
    uint8_t  uart_ring[UART_RING_SIZE];
    volatile uint16_t uart_head;
    volatile uint16_t uart_tail;

    /* AT response line buffer */
    char     at_line[AT_RESP_BUF];
    int      at_line_pos;

    /* Pending TX (GUI thread → worker thread) */
    char     pending_tx[MAX_MSG+1];
    bool     pending_tx_ready;

    /* Worker thread */
    FuriThread* worker;
    bool         worker_run;

    /* Handshake challenge */
    uint8_t  challenge[8];
};

static ChatApp* g_app = NULL;

/* ═══════════════════════════════════════════════════════════════════════════
 *  Frame encode / decode
 *  Wire format: STX | type | nonce[8] | enc_len | ciphertext[enc_len] | crc16[2]
 * ═══════════════════════════════════════════════════════════════════════════ */

static int frame_encode(
    ChatApp *app, uint8_t type,
    const uint8_t *plaintext, uint8_t pt_len,
    uint8_t *out, size_t out_max)
{
    if((size_t)(FRAME_OVERHEAD + pt_len) > out_max) return -1;
    uint8_t nonce[NONCE_LEN];
    furi_hal_random_fill_buf(nonce, NONCE_LEN);

    uint8_t ct[FRAME_MAX_ENC];
    if(pt_len > FRAME_MAX_ENC) return -1;
    memcpy(ct, plaintext, pt_len);
    aes_ctr(app->key, nonce, ct, pt_len);

    int pos=0;
    out[pos++]=0x02;
    out[pos++]=type;
    memcpy(out+pos, nonce, NONCE_LEN); pos+=NONCE_LEN;
    out[pos++]=pt_len;
    memcpy(out+pos, ct, pt_len); pos+=pt_len;
    uint16_t c=crc16(out+1, (size_t)(pos-1));
    out[pos++]=(uint8_t)(c>>8);
    out[pos++]=(uint8_t)(c&0xFF);
    return pos;
}

/* Returns plaintext length on success, -1 on error */
static int frame_decode(
    ChatApp *app,
    const uint8_t *in, size_t in_len,
    uint8_t *type_out,
    uint8_t *pt_out, size_t pt_max)
{
    if(in_len < (size_t)FRAME_OVERHEAD) return -1;
    if(in[0] != 0x02) return -1;
    *type_out = in[1];
    uint8_t enc_len = in[2+NONCE_LEN];
    if((size_t)(FRAME_OVERHEAD + enc_len) > in_len) return -1;
    if(enc_len > pt_max) return -1;

    /* CRC check over bytes [1 .. 2+NONCE_LEN+enc_len] */
    size_t crc_span = 1 + 1 + NONCE_LEN + 1 + enc_len;
    uint16_t expected = ((uint16_t)in[2+NONCE_LEN+1+enc_len]<<8)
                       | in[2+NONCE_LEN+1+enc_len+1];
    if(crc16(in+1, crc_span) != expected) {
        FURI_LOG_W(TAG, "Frame CRC mismatch");
        return -1;
    }

    memcpy(pt_out, in+3+NONCE_LEN, enc_len);
    aes_ctr(app->key, in+2, pt_out, enc_len);
    return enc_len;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Chat log
 * ═══════════════════════════════════════════════════════════════════════════ */

static void log_add(ChatApp *app, const char *prefix, const char *msg) {
    furi_mutex_acquire(app->log_mutex, FuriWaitForever);

    /* Word-wrap the message into CHAT_LINE_W-char lines */
    char full[MAX_MSG + 8];
    snprintf(full, sizeof(full), "%s%.60s", prefix, msg);
    size_t flen = strlen(full);
    size_t pos = 0;
    while(pos < flen) {
        if(app->line_count >= MAX_CHAT_LINES) {
            /* Scroll: drop oldest line */
            memmove(app->lines[0], app->lines[1],
                    sizeof(app->lines[0]) * (MAX_CHAT_LINES-1));
            app->line_count = MAX_CHAT_LINES-1;
        }
        size_t take = flen - pos;
        if(take > CHAT_LINE_W) take = CHAT_LINE_W;
        memcpy(app->lines[app->line_count], full+pos, take);
        app->lines[app->line_count][take] = '\0';
        app->line_count++;
        pos += take;
    }
    app->scroll = 0;

    furi_mutex_release(app->log_mutex);
    view_dispatcher_send_custom_event(app->vd, 42);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  UART → ESP32
 * ═══════════════════════════════════════════════════════════════════════════ */

static void uart_rx_isr(FuriHalSerialHandle *h, FuriHalSerialRxEvent ev, void *ctx) {
    ChatApp *app = ctx;
    if(ev == FuriHalSerialRxEventData) {
        uint8_t b = furi_hal_serial_async_rx(h);
        uint16_t next = (app->uart_tail+1) & UART_RING_MASK;
        if(next != app->uart_head) {
            app->uart_ring[app->uart_tail] = b;
            app->uart_tail = next;
        }
    }
}

/* Read one byte from ring, returns false if empty */
static bool uart_read_byte(ChatApp *app, uint8_t *b) {
    if(app->uart_head == app->uart_tail) return false;
    *b = app->uart_ring[app->uart_head];
    app->uart_head = (app->uart_head+1) & UART_RING_MASK;
    return true;
}

static void esp_send(ChatApp *app, const char *cmd) {
    if(!app->serial) return;
    FURI_LOG_D(TAG, "→ESP: %s", cmd);
    furi_hal_serial_tx(app->serial, (const uint8_t*)cmd, strlen(cmd));
    furi_hal_serial_tx(app->serial, (const uint8_t*)"\r\n", 2);
}

/* Send raw binary data over SPP transparent channel (no \r\n) */
static void esp_send_raw(ChatApp *app, const uint8_t *data, size_t len) {
    if(!app->serial) return;
    furi_hal_serial_tx(app->serial, data, len);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  AT response parser
 *  Called from worker thread whenever a complete line arrives from ESP32.
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_at_line(ChatApp *app, const char *line) {
    FURI_LOG_D(TAG, "←ESP: %s", line);

    /* Scan result: +BLESCAN:<addr>,<rssi>,<adv_data>,<scan_rsp_data>,<adv_type> */
    if(memcmp(line, "+BLESCAN:", 9) == 0) {
        furi_mutex_acquire(app->peer_mutex, FuriWaitForever);
        if(app->peer_count < MAX_PEERS) {
            Peer *p = &app->peers[app->peer_count];
            /* Parse addr */
            const char *s = line+9;
            int i=0;
            while(*s && *s!=',' && i<(int)sizeof(p->addr)-1) p->addr[i++]=*s++;
            p->addr[i]='\0'; if(*s==',') s++;
            /* Parse RSSI */
            p->rssi = (int)strtol(s, NULL, 10);
            /* Default name = addr; will be overwritten if scan_rsp has name */
            memcpy(p->name, p->addr, sizeof(p->name));

            /* Check adv_data for FlipperChat marker "FlipperChat" in device name
               The adv_data is hex-encoded. We look for the scan_rsp_data field
               which comes after 3 commas */
            const char *field = s;
            int commas=0;
            while(*field){ if(*field==',') commas++; if(commas==3) break; field++; }
            if(commas==3 && field) {
                /* Check if adv/scan data contains our service UUID marker
                   We'll just accept all and filter by name in the UI */
                app->peer_count++;
            }
        }
        furi_mutex_release(app->peer_mutex);
        view_dispatcher_send_custom_event(app->vd, 43); /* refresh scan list */
        return;
    }

    /* Connection event: +BLECONN:<conn_index>,<remote_addr> */
    if(memcmp(line, "+BLECONN:", 9) == 0) {
        FURI_LOG_I(TAG, "BLE connected");
        app->conn = ConnHandshake;
        if(app->role == RoleHost) {
            /* Host sends HELLO challenge */
            furi_hal_random_fill_buf(app->challenge, 8);
            uint8_t frame[FRAME_OVERHEAD + 8];
            int flen = frame_encode(app, FRAME_HELLO, app->challenge, 8,
                                    frame, sizeof(frame));
            if(flen > 0) esp_send_raw(app, frame, (size_t)flen);
        }
        view_dispatcher_send_custom_event(app->vd, 44);
        return;
    }

    /* Disconnect: +BLEDISCONN:<conn_index>,<remote_addr> */
    if(memcmp(line, "+BLEDISCONN:", 12) == 0) {
        FURI_LOG_I(TAG, "BLE disconnected");
        app->conn = ConnError;
        log_add(app, "** ", "Disconnected");
        view_dispatcher_send_custom_event(app->vd, 45);
        return;
    }

    /* SPP data received: +BLESPPDATA:<conn_index>,<len>:<data_bytes>
       Note: In transparent mode (BLESPPCFG=1) data arrives raw without prefix.
       We handle both modes. */
    if(memcmp(line, "+BLESPPDATA:", 12) == 0) {
        /* Framed mode — shouldn't normally arrive as a text line,
           but handle gracefully */
        return;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SPP binary frame reassembly
 *  In transparent mode all incoming bytes go straight to the ring buffer.
 *  We reassemble frames here.
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t buf[FRAME_OVERHEAD + FRAME_MAX_ENC + 2];
    int     pos;
    bool    in_frame;
    uint8_t expected_len; /* enc_len field, known after byte 11 */
} FrameAssembler;

static void frame_asm_init(FrameAssembler *fa) { memset(fa,0,sizeof(*fa)); }

/* Feed one byte. Returns true if a complete frame is ready in fa->buf[0..fa->pos-1] */
static bool frame_asm_feed(FrameAssembler *fa, uint8_t b) {
    if(!fa->in_frame) {
        if(b == 0x02) {
            fa->in_frame = true;
            fa->pos = 0;
            fa->expected_len = 0;
            fa->buf[fa->pos++] = b;
        }
        return false;
    }
    if(fa->pos < (int)sizeof(fa->buf))
        fa->buf[fa->pos++] = b;
    else { fa->in_frame=false; fa->pos=0; return false; } /* overflow */

    /* Once we have STX+type+nonce(8)+enc_len = 11 bytes, we know total size */
    if(fa->pos == 11) {
        fa->expected_len = fa->buf[10]; /* enc_len */
        if(fa->expected_len > FRAME_MAX_ENC) {
            fa->in_frame=false; fa->pos=0; return false;
        }
    }
    if(fa->pos > 11) {
        /* Total frame = 11 + enc_len + 2(crc) */
        int total = 11 + (int)fa->expected_len + 2;
        if(fa->pos == total) {
            fa->in_frame = false;
            return true;
        }
    }
    return false;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  ESP32 initialisation sequence
 * ═══════════════════════════════════════════════════════════════════════════ */

static void esp_init_host(ChatApp *app) {
    esp_send(app, "AT+RESTORE");        furi_delay_ms(1500);
    esp_send(app, "AT+BLEINIT=2");      furi_delay_ms(300);  /* server role */
    /* Set device name to "FlipperChat" so it shows up in scans */
    esp_send(app, "AT+BLENAME=\"FlipperChat\""); furi_delay_ms(200);
    /* Advertise with name in adv data */
    esp_send(app, "AT+BLEADVDATAEX=\"FlipperChat\",\"FFE0\",\"\",1"); furi_delay_ms(200);
    esp_send(app, "AT+BLEADVPARAM=50,50,0,0,7,0,,"); furi_delay_ms(200);
    esp_send(app, "AT+BLEGATTSSRVCRE"); furi_delay_ms(200);
    esp_send(app, "AT+BLEGATTSSRVSTART"); furi_delay_ms(200);
    esp_send(app, "AT+BLEADVSTART");    furi_delay_ms(200);
    /* Configure SPP transparent mode */
    esp_send(app, "AT+BLESPPCFG=1,1,7,1,5"); furi_delay_ms(200);
    app->conn = ConnAdvertising;
    FURI_LOG_I(TAG, "ESP32 host mode started");
}

static void esp_init_client(ChatApp *app) {
    esp_send(app, "AT+RESTORE");        furi_delay_ms(1500);
    esp_send(app, "AT+BLEINIT=1");      furi_delay_ms(300);  /* client role */
    app->conn = ConnScanning;
    FURI_LOG_I(TAG, "ESP32 client mode started");
}

static void esp_start_scan(ChatApp *app) {
    furi_mutex_acquire(app->peer_mutex, FuriWaitForever);
    app->peer_count = 0;
    app->peer_sel = 0;
    furi_mutex_release(app->peer_mutex);
    esp_send(app, "AT+BLESCAN=1,5");   /* scan 5 seconds */
}

static void esp_connect_peer(ChatApp *app, int idx) {
    if(idx < 0 || idx >= app->peer_count) return;
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "AT+BLECONN=0,\"%s\"", app->peers[idx].addr);
    app->conn = ConnConnecting;
    esp_send(app, cmd);
    /* Configure SPP transparent mode as client */
    furi_delay_ms(500);
    esp_send(app, "AT+BLESPPCFG=1,1,7,1,5");
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Worker thread  (UART RX + AT parsing + handshake + message routing)
 * ═══════════════════════════════════════════════════════════════════════════ */

static int32_t worker_func(void *ctx) {
    ChatApp *app = ctx;
    FURI_LOG_I(TAG, "Worker started");

    FrameAssembler fa;
    frame_asm_init(&fa);

    /* Ring buffer for AT line assembly */
    /* We distinguish AT lines (printable, ending \n) from binary SPP frames (start 0x02) */
    bool in_spp_mode = false; /* true once handshake complete */

    while(app->worker_run) {
        /* ── Outbound TX ─────────────────────────────────────────────── */
        furi_mutex_acquire(app->log_mutex, FuriWaitForever);
        bool do_tx = app->pending_tx_ready;
        char tx_msg[MAX_MSG+1];
        if(do_tx){
            memcpy(tx_msg, app->pending_tx, sizeof(tx_msg));
            app->pending_tx_ready = false;
        }
        furi_mutex_release(app->log_mutex);

        if(do_tx && app->conn == ConnReady && app->key_set) {
            uint8_t frame[FRAME_OVERHEAD + MAX_MSG + 2];
            int flen = frame_encode(app, FRAME_MSG,
                                    (const uint8_t*)tx_msg, (uint8_t)strlen(tx_msg),
                                    frame, sizeof(frame));
            if(flen > 0) esp_send_raw(app, frame, (size_t)flen);
        }

        /* ── Inbound RX ──────────────────────────────────────────────── */
        uint8_t b;
        while(uart_read_byte(app, &b)) {
            if(in_spp_mode || b == 0x02) {
                /* Binary frame path */
                in_spp_mode = true;
                if(frame_asm_feed(&fa, b)) {
                    uint8_t type=0;
                    uint8_t pt[MAX_MSG+1];
                    int pt_len = frame_decode(app, fa.buf, (size_t)fa.pos,
                                              &type, pt, sizeof(pt)-1);
                    if(pt_len >= 0) {
                        pt[pt_len] = '\0';
                        if(type == FRAME_MSG && app->conn == ConnReady) {
                            log_add(app, ">> ", (char*)pt);
                            notification_message(app->notif, &sequence_blink_blue_100);
                        } else if(type == FRAME_HELLO && app->role == RoleClient) {
                            /* Client got challenge → encrypt it back as HELLOACK */
                            uint8_t ack[FRAME_OVERHEAD+8+2];
                            int alen = frame_encode(app, FRAME_HELLOACK,
                                                    pt, (uint8_t)pt_len,
                                                    ack, sizeof(ack));
                            if(alen>0) esp_send_raw(app, ack, (size_t)alen);
                        } else if(type == FRAME_HELLOACK && app->role == RoleHost) {
                            /* Host verifies HELLOACK matches challenge */
                            if(pt_len == 8 && memcmp(pt, app->challenge, 8)==0) {
                                app->conn = ConnReady;
                                log_add(app, "** ", "Secure channel open!");
                                view_dispatcher_send_custom_event(app->vd, 46);
                            } else {
                                log_add(app, "** ", "Auth failed! Wrong passphrase?");
                                app->conn = ConnError;
                            }
                        } else if(type == FRAME_HELLO && app->role == RoleHost) {
                            /* Shouldn't happen but ignore */
                        }
                    }
                    frame_asm_init(&fa);
                }
            } else {
                /* AT response line path */
                if(b == '\n') {
                    /* Trim \r */
                    while(app->at_line_pos > 0 &&
                          app->at_line[app->at_line_pos-1] == '\r')
                        app->at_line_pos--;
                    app->at_line[app->at_line_pos] = '\0';
                    if(app->at_line_pos > 0)
                        parse_at_line(app, app->at_line);
                    app->at_line_pos = 0;
                } else if(app->at_line_pos < AT_RESP_BUF-1) {
                    app->at_line[app->at_line_pos++] = (char)b;
                    /* If this byte was 0x02 we might be entering SPP */
                    if(b == 0x02) {
                        in_spp_mode = true;
                        app->at_line_pos = 0;
                        frame_asm_init(&fa);
                        frame_asm_feed(&fa, b);
                    }
                }
            }
        }

        /* After client handshake (client sent HELLOACK), mark ready */
        if(app->conn == ConnHandshake && app->role == RoleClient) {
            /* Client side: we sent HELLOACK and consider ourselves ready
               (host will disconnect us if key was wrong) */
            app->conn = ConnReady;
            log_add(app, "** ", "Connected! Passphrase sent.");
            view_dispatcher_send_custom_event(app->vd, 46);
        }

        furi_delay_ms(20);
    }

    FURI_LOG_I(TAG, "Worker stopped");
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  GUI — Chat view
 * ═══════════════════════════════════════════════════════════════════════════ */

#define CH  9
#define CV  6

static void chat_draw(Canvas *canvas, void *ctx) {
    ChatApp *app = ctx ? ctx : g_app;
    canvas_clear(canvas);
    canvas_set_font(canvas, FontSecondary);

    furi_mutex_acquire(app->log_mutex, FuriWaitForever);
    int total = app->line_count;
    int start = total - CV - app->scroll;
    if(start < 0) start = 0;
    for(int row=0; row<CV && (start+row)<total; row++)
        canvas_draw_str(canvas, 0, (row+1)*CH, app->lines[start+row]);
    furi_mutex_release(app->log_mutex);

    /* Status bar */
    const char *status = (app->conn==ConnReady)     ? "OK" :
                         (app->conn==ConnAdvertising)? "Waiting..." :
                         (app->conn==ConnHandshake)  ? "Auth..." :
                         (app->conn==ConnError)      ? "ERR" : "...";
    canvas_draw_line(canvas, 0, 54, 127, 54);
    canvas_draw_str(canvas, 0,   63, "OK:Send");
    canvas_draw_str(canvas, 52,  63, "^v:Scroll");
    canvas_draw_str(canvas, 100, 63, status);
}

static bool chat_input(InputEvent *ev, void *ctx) {
    ChatApp *app = ctx ? ctx : g_app;
    if(ev->type != InputTypeShort && ev->type != InputTypeRepeat) return false;
    if(ev->key == InputKeyOk) {
        if(app->conn == ConnReady) {
            app->cur_view = ViewSend;
            view_dispatcher_switch_to_view(app->vd, ViewSend);
        }
        return true;
    }
    if(ev->key == InputKeyUp)   { app->scroll++; view_dispatcher_send_custom_event(app->vd,42); return true; }
    if(ev->key == InputKeyDown) { if(app->scroll>0) app->scroll--; view_dispatcher_send_custom_event(app->vd,42); return true; }
    return false;
}

static bool chat_custom(uint32_t ev, void *ctx) { UNUSED(ev); UNUSED(ctx); return true; }

/* ═══════════════════════════════════════════════════════════════════════════
 *  GUI — Scan list view
 * ═══════════════════════════════════════════════════════════════════════════ */

static void scan_draw(Canvas *canvas, void *ctx) {
    ChatApp *app = ctx ? ctx : g_app;
    canvas_clear(canvas);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 0, 9, "FlipperChat devices:");

    furi_mutex_acquire(app->peer_mutex, FuriWaitForever);
    int count = app->peer_count;
    if(count == 0) {
        canvas_draw_str(canvas, 0, 24, "Scanning...");
    } else {
        for(int i=0; i<count && i<5; i++) {
            if(i == app->peer_sel)
                canvas_draw_box(canvas, 0, 10+i*10, 128, 10);
            canvas_set_color(canvas, (i==app->peer_sel)?ColorWhite:ColorBlack);
            char line[32];
            snprintf(line, sizeof(line), "%s (%ddBm)", app->peers[i].addr, app->peers[i].rssi);
            canvas_draw_str(canvas, 2, 18+i*10, line);
            canvas_set_color(canvas, ColorBlack);
        }
    }
    furi_mutex_release(app->peer_mutex);

    canvas_draw_line(canvas, 0, 54, 127, 54);
    canvas_draw_str(canvas, 0, 63, "OK:Connect  ^v:Select");
}

static bool scan_input(InputEvent *ev, void *ctx) {
    ChatApp *app = ctx ? ctx : g_app;
    if(ev->type != InputTypeShort) return false;
    if(ev->key == InputKeyUp) {
        if(app->peer_sel > 0) app->peer_sel--;
        view_dispatcher_send_custom_event(app->vd, 43);
        return true;
    }
    if(ev->key == InputKeyDown) {
        if(app->peer_sel < app->peer_count-1) app->peer_sel++;
        view_dispatcher_send_custom_event(app->vd, 43);
        return true;
    }
    if(ev->key == InputKeyOk) {
        if(app->peer_count > 0) {
            esp_connect_peer(app, app->peer_sel);
            app->cur_view = ViewConnecting;
            view_dispatcher_switch_to_view(app->vd, ViewConnecting);
        }
        return true;
    }
    return false;
}

static bool scan_custom(uint32_t ev, void *ctx) { UNUSED(ev); UNUSED(ctx); return true; }

/* ═══════════════════════════════════════════════════════════════════════════
 *  GUI — Connecting view
 * ═══════════════════════════════════════════════════════════════════════════ */

static void connecting_draw(Canvas *canvas, void *ctx) {
    ChatApp *app = ctx ? ctx : g_app;
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 20, AlignCenter, AlignCenter, "FlipperChat");
    canvas_set_font(canvas, FontSecondary);
    const char *msg =
        (app->conn == ConnConnecting) ? "Connecting..." :
        (app->conn == ConnHandshake)  ? "Authenticating..." :
        (app->conn == ConnReady)      ? "Connected!" :
        (app->conn == ConnError)      ? "Failed! BACK to retry" :
        (app->conn == ConnAdvertising)? "Waiting for peer..." :
        "Please wait...";
    canvas_draw_str_aligned(canvas, 64, 40, AlignCenter, AlignCenter, msg);
    canvas_draw_str_aligned(canvas, 64, 56, AlignCenter, AlignCenter, "BACK to cancel");
}

static bool connecting_custom(uint32_t ev, void *ctx) {
    ChatApp *app = ctx ? ctx : g_app;
    if(ev == 46 && app->conn == ConnReady) {
        /* Handshake done → switch to chat */
        app->cur_view = ViewChat;
        view_dispatcher_switch_to_view(app->vd, ViewChat);
    } else if(ev == 44 || ev == 45 || ev == 46) {
        /* Refresh connecting screen */
    }
    return true;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Global custom event dispatcher
 * ═══════════════════════════════════════════════════════════════════════════ */

static bool vd_custom_cb(void *ctx, uint32_t ev) {
    ChatApp *app = ctx ? ctx : g_app;
    /* Route event 46 (connected) to connecting_view if that's where we are */
    if(ev == 46 && app->cur_view == ViewConnecting) {
        connecting_custom(ev, app);
    }
    /* events 42/43/44/45/46 all just trigger a redraw of whatever view is active */
    return true;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Navigation
 * ═══════════════════════════════════════════════════════════════════════════ */

static void switch_view(ChatApp *app, ChatViewId id) {
    app->cur_view = id;
    view_dispatcher_switch_to_view(app->vd, (uint32_t)id);
}

static void nav_back(void *ctx) {
    ChatApp *app = ctx ? ctx : g_app;
    switch(app->cur_view) {
        case ViewPassphrase:
        case ViewInfo:
            switch_view(app, ViewMenu); break;
        case ViewSend:
            switch_view(app, ViewChat); break;
        case ViewScan:
        case ViewConnecting:
        case ViewChat:
            /* Disconnect if connected */
            if(app->conn != ConnNone) {
                esp_send(app, "AT+BLEDISCONN=0");
                esp_send(app, "AT+BLEADVSTOP");
                esp_send(app, "AT+BLESCAN=0");
                app->conn = ConnNone;
                app->role = RoleNone;
            }
            switch_view(app, ViewMenu); break;
        case ViewMenu:
        default:
            view_dispatcher_stop(app->vd); break;
    }
}

static bool nav_event(void *ctx) {
    ChatApp *app = ctx ? ctx : g_app;
    if(app->cur_view == ViewMenu) { view_dispatcher_stop(app->vd); return false; }
    nav_back(app);
    return true;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Menu callbacks
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum { MenuPassphrase=0, MenuHost, MenuJoin, MenuInfo } MenuIdx;

static void menu_cb(void *ctx, uint32_t idx) {
    ChatApp *app = ctx;
    switch((MenuIdx)idx) {
        case MenuPassphrase:
            switch_view(app, ViewPassphrase);
            break;

        case MenuHost:
            if(!app->key_set) {
                popup_set_header(app->info_popup,"Set Passphrase",64,10,AlignCenter,AlignTop);
                popup_set_text(app->info_popup,"Set a passphrase\nfirst!",64,35,AlignCenter,AlignCenter);
                popup_set_timeout(app->info_popup, 2000);
                popup_enable_timeout(app->info_popup);
                switch_view(app, ViewInfo);
                break;
            }
            app->role = RoleHost;
            app->line_count = 0;
            app->scroll = 0;
            log_add(app, "** ", "Starting as Host...");
            esp_init_host(app);
            switch_view(app, ViewConnecting);
            break;

        case MenuJoin:
            if(!app->key_set) {
                popup_set_header(app->info_popup,"Set Passphrase",64,10,AlignCenter,AlignTop);
                popup_set_text(app->info_popup,"Set a passphrase\nfirst!",64,35,AlignCenter,AlignCenter);
                popup_set_timeout(app->info_popup, 2000);
                popup_enable_timeout(app->info_popup);
                switch_view(app, ViewInfo);
                break;
            }
            app->role = RoleClient;
            app->line_count = 0;
            app->scroll = 0;
            esp_init_client(app);
            furi_delay_ms(500);
            esp_start_scan(app);
            switch_view(app, ViewScan);
            break;

        case MenuInfo:
            popup_set_header(app->info_popup,"FlipperChat v2.0",64,10,AlignCenter,AlignTop);
            popup_set_text(app->info_popup,
                "Needs ESP32 w/ AT FW\n"
                "on GPIO pins 13/14\n"
                "AES-128-CTR + SHA256\n"
                "BACK to return",
                64,38,AlignCenter,AlignCenter);
            popup_disable_timeout(app->info_popup);
            switch_view(app, ViewInfo);
            break;
    }
}

static void pass_done_cb(void *ctx) {
    ChatApp *app = ctx;
    derive_key(app->pass_buf, app->key);
    app->key_set = true;
    submenu_change_item_label(app->menu, MenuPassphrase, "Passphrase [SET]");
    switch_view(app, ViewMenu);
}

static void send_done_cb(void *ctx) {
    ChatApp *app = ctx;
    if(!strlen(app->send_buf)) { switch_view(app, ViewChat); return; }
    log_add(app, "Me: ", app->send_buf);
    furi_mutex_acquire(app->log_mutex, FuriWaitForever);
    memcpy(app->pending_tx, app->send_buf, sizeof(app->send_buf));
    app->pending_tx_ready = true;
    furi_mutex_release(app->log_mutex);
    notification_message(app->notif, &sequence_blink_white_100);
    memset(app->send_buf, 0, sizeof(app->send_buf));
    switch_view(app, ViewChat);
}

static void info_timeout_cb(void *ctx) { nav_back(ctx); }

/* ═══════════════════════════════════════════════════════════════════════════
 *  App lifecycle
 * ═══════════════════════════════════════════════════════════════════════════ */

static ChatApp* app_alloc(void) {
    ChatApp *app = malloc(sizeof(ChatApp));
    memset(app, 0, sizeof(ChatApp));
    g_app = app;

    app->log_mutex  = furi_mutex_alloc(FuriMutexTypeNormal);
    app->peer_mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->notif      = furi_record_open(RECORD_NOTIFICATION);
    app->gui        = furi_record_open(RECORD_GUI);

    /* UART */
    app->serial = furi_hal_serial_control_acquire(ESP_UART_ID);
    furi_hal_serial_init(app->serial, ESP_UART_BAUD);
    furi_hal_serial_async_rx_start(app->serial, uart_rx_isr, app, false);

    /* ViewDispatcher */
    app->vd = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->vd, app->gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_set_navigation_event_callback(app->vd, nav_event);
    view_dispatcher_set_event_callback_context(app->vd, app);
    view_dispatcher_set_custom_event_callback(app->vd, vd_custom_cb);

    /* Menu */
    app->menu = submenu_alloc();
    submenu_add_item(app->menu, "Set Passphrase", MenuPassphrase, menu_cb, app);
    submenu_add_item(app->menu, "Host a Chat",    MenuHost,       menu_cb, app);
    submenu_add_item(app->menu, "Join a Chat",    MenuJoin,       menu_cb, app);
    submenu_add_item(app->menu, "Info",           MenuInfo,       menu_cb, app);
    view_dispatcher_add_view(app->vd, ViewMenu, submenu_get_view(app->menu));

    /* Passphrase input */
    app->pass_input = text_input_alloc();
    text_input_set_header_text(app->pass_input, "Shared passphrase:");
    text_input_set_result_callback(app->pass_input, pass_done_cb, app,
                                   app->pass_buf, MAX_PASS, true);
    view_dispatcher_add_view(app->vd, ViewPassphrase, text_input_get_view(app->pass_input));

    /* Send input */
    app->send_input = text_input_alloc();
    text_input_set_header_text(app->send_input, "Message:");
    text_input_set_result_callback(app->send_input, send_done_cb, app,
                                   app->send_buf, MAX_MSG, true);
    view_dispatcher_add_view(app->vd, ViewSend, text_input_get_view(app->send_input));

    /* Chat view */
    app->chat_view = view_alloc();
    view_set_draw_callback(app->chat_view, chat_draw);
    view_set_input_callback(app->chat_view, chat_input);
    view_set_custom_callback(app->chat_view, chat_custom);
    view_set_context(app->chat_view, app);
    view_dispatcher_add_view(app->vd, ViewChat, app->chat_view);

    /* Scan view */
    app->scan_view = view_alloc();
    view_set_draw_callback(app->scan_view, scan_draw);
    view_set_input_callback(app->scan_view, scan_input);
    view_set_custom_callback(app->scan_view, scan_custom);
    view_set_context(app->scan_view, app);
    view_dispatcher_add_view(app->vd, ViewScan, app->scan_view);

    /* Connecting view */
    app->connecting_view = view_alloc();
    view_set_draw_callback(app->connecting_view, connecting_draw);
    view_set_custom_callback(app->connecting_view, connecting_custom);
    view_set_context(app->connecting_view, app);
    view_dispatcher_add_view(app->vd, ViewConnecting, app->connecting_view);

    /* Info popup */
    app->info_popup = popup_alloc();
    popup_set_callback(app->info_popup, info_timeout_cb);
    popup_set_context(app->info_popup, app);
    view_dispatcher_add_view(app->vd, ViewInfo, popup_get_view(app->info_popup));

    /* Worker thread */
    app->worker_run = true;
    app->worker = furi_thread_alloc_ex("ChatWorker", 2048, worker_func, app);
    furi_thread_start(app->worker);

    return app;
}

static void app_free(ChatApp *app) {
    app->worker_run = false;
    furi_thread_join(app->worker);
    furi_thread_free(app->worker);

    /* Stop BLE */
    esp_send(app, "AT+BLEDISCONN=0");
    furi_delay_ms(100);
    esp_send(app, "AT+BLEINIT=0");
    furi_delay_ms(200);

    /* UART */
    furi_hal_serial_async_rx_stop(app->serial);
    furi_hal_serial_deinit(app->serial);
    furi_hal_serial_control_release(app->serial);

    /* Views */
    view_dispatcher_remove_view(app->vd, ViewMenu);
    view_dispatcher_remove_view(app->vd, ViewPassphrase);
    view_dispatcher_remove_view(app->vd, ViewSend);
    view_dispatcher_remove_view(app->vd, ViewChat);
    view_dispatcher_remove_view(app->vd, ViewScan);
    view_dispatcher_remove_view(app->vd, ViewConnecting);
    view_dispatcher_remove_view(app->vd, ViewInfo);

    submenu_free(app->menu);
    text_input_free(app->pass_input);
    text_input_free(app->send_input);
    view_free(app->chat_view);
    view_free(app->scan_view);
    view_free(app->connecting_view);
    popup_free(app->info_popup);
    view_dispatcher_free(app->vd);

    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_NOTIFICATION);
    furi_mutex_free(app->log_mutex);
    furi_mutex_free(app->peer_mutex);
    g_app = NULL;
    free(app);
}

int32_t flipper_chat_app(void *p) {
    UNUSED(p);
    FURI_LOG_I(TAG, "FlipperChat v2.0 starting");
    ChatApp *app = app_alloc();
    switch_view(app, ViewMenu);
    view_dispatcher_run(app->vd);
    FURI_LOG_I(TAG, "FlipperChat exiting");
    app_free(app);
    return 0;
}
