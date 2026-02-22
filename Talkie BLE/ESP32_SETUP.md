# TalkieBLE v2.0 — ESP32 Hardware Setup Guide

## What you need (×2, one per Flipper)

| Part | Notes |
|------|-------|
| ESP32 development board | Any ESP32 — ESP32-DevKitC, WROOM, WROVER, etc. |
| 4 jumper wires (female-female) | GPIO header → ESP32 |
| Espressif ESP-AT firmware | Free download from Espressif |

---

## Step 1 — Flash ESP-AT firmware onto the ESP32

Download the latest ESP-AT binary for your chip from:
https://github.com/espressif/esp-at/releases

For a standard **ESP32 WROOM/WROVER** module, download:
`ESP32-WROOM-32_AT_Vx.x.x.x.zip`

Flash with esptool:
```bash
pip install esptool

# Extract the zip, then from the extracted folder:
esptool.py --chip esp32 --port /dev/ttyUSB0 --baud 115200 write_flash \
    0x0     bootloader/bootloader.bin \
    0x8000  partition_table/partition-table.bin \
    0xd000  ota_data_initial.bin \
    0x1e000 at_customize.bin \
    0x20000 esp-at.bin
```

Replace `/dev/ttyUSB0` with your ESP32's serial port (COMx on Windows).

**Verify it works**: Open a serial terminal at 115200 baud, type `AT`, press Enter.
You should see `OK`.

---

## Step 2 — Wire the ESP32 to the Flipper Zero GPIO header

```
Flipper Zero GPIO          ESP32
─────────────────────────────────────────────────
Pin  1  (5V)      ──────→  5V    (or VIN)
Pin 18  (GND)     ──────→  GND
Pin 13  (TX/PA7)  ──────→  RX0   (GPIO3 on ESP32)
Pin 14  (RX/PA6)  ──────→  TX0   (GPIO1 on ESP32)
```

> ⚠️  **Enable 5V on the Flipper first!**
> Go to: Flipper menu → GPIO → Enable 5V on Pin 1
> The ESP32 will NOT work on 3.3V from Pin 9 — it needs 5V.

> ⚠️  **3.3V logic on ESP32 TX → Flipper RX is fine** (Flipper GPIO is 5V tolerant for input).

---

## Step 3 — Verify UART communication from the Flipper

With the ESP32 wired up and the Flipper running TalkieBLE:

1. Open TalkieBLE on both Flippers
2. Set the same passphrase on both
3. On the **Host** Flipper: select **"Host a Chat"**
4. On the **Client** Flipper: select **"Join a Chat"**
5. The client Flipper will scan for 5 seconds and show a list of found devices
6. Select the host's MAC address → press OK → connection is established
7. The chat screen opens on both Flippers

---

## How it works internally

```
Flipper A ←─UART─→ ESP32-A (server/peripheral role)
                         │
                    BLE connection
                         │
Flipper B ←─UART─→ ESP32-B (client/central role)
```

The ESP32s communicate using **BLE SPP transparent transmission mode**
(`AT+BLESPPCFG`). Once connected, every byte written to the UART on one side
comes out on the other side's UART — the ESP32s act as a transparent
wireless UART bridge.

The Flipper app sits on top of this transparent channel and handles:
- **AES-128-CTR encryption** (self-contained, no mbedTLS needed)
- **SHA-256 key derivation** from the shared passphrase
- **Challenge-response handshake** to verify both sides share the same key
  before the chat opens
- **CRC-16 frame integrity** on every message

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| No scan results | Check wiring, ensure 5V enabled on Flipper, verify ESP-AT responds to `AT` |
| "Auth failed! Wrong passphrase?" | Make sure BOTH Flippers have the exact same passphrase entered |
| Connection drops | ESP32 may be brownout — check 5V supply is stable |
| ESP32 not responding | Re-flash ESP-AT firmware; some boards ship with different firmware |
| Can't find `AT+BLEADVDATAEX` | Your ESP-AT version may be older — try `AT+BLEADVDATA` with manual hex |

---

## ESP-AT version notes

This app uses:
- `AT+BLENAME` — set device name (all versions)
- `AT+BLEADVDATAEX` — set adv data with name (v2.1+)
- `AT+BLESPPCFG` — transparent SPP mode (v2.1+)
- `AT+BLESCAN` — scan for devices (all versions)
- `AT+BLECONN` — connect (all versions)

**Minimum recommended ESP-AT version: v2.4.0**

Download: https://github.com/espressif/esp-at/releases
