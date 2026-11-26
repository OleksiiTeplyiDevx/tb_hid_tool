# TB HID Tool

A small desktop tool (Dear PyGui + hidapi) to talk to the TB protocol HID interface
of the Turtle Beach Stealth Pro II over USB. It is a development tool: send raw frames,
read the device FW version and update the firmware (POC).

## Requirements

- Windows, Python 3.10+
- `pip install -r requirements.txt` (`dearpygui`, `hidapi`)
  - the package must be `hidapi`, NOT `hid` (`pip uninstall hid` if it is installed)

## Run

```
python tb_hid_tool.py
```

or `run_tb_hid_tool.bat`. Option `--demo` fills the log with sample lines.

## Usage

1. Pick the device on the left. Only Turtle Beach devices with the TB protocol interface
   (vendor VID 0x10F5, usage page 0xFF42) are listed. Press **Connect**.
   With **Auto-reconnect** the tool reconnects after the device reboots.
2. On connect the tool sends GET_PROPERTY (FW version) and shows it above the tabs:
   `Device FW version: 1.31.276.0`. **Read FW version** (Firmware update tab) and the
   `Get FW version` default command repeat the request.
3. Send frames from the tabs:
   - **Raw hex** - first byte is the report ID, padded with zeros to the report size (64). Has an echo test and repeat.
   - **Frame builder** - report ID + opcode + payload.
   - **Firmware update** - see below.
4. The log shows TX / RX / NOTIFY with a hex dump.

### Default commands

The list on the left comes from `tb_commands.json` (next to the script). Click an item to load
it into Raw hex, **Send** sends it. Add your own with the save fields. `"action": "fw_version"`
makes an item send the FW version request instead of raw hex.

## Firmware update (POC)

Updates the master over the dedicated USB HID interface.

1. Build the master firmware of Stealth Pro II. The WSL build also creates `fota_package.bin`
   (`wsl_make_fota_package.sh`) and copies it to the Windows artifacts folder.
2. Open the **Firmware update** tab, pick the file (default `..\master\fota_package.bin`).
   The tool shows size, block count and CRC32.
3. Press **Start update**. The progress bar shows `block N / M` and the elapsed time.
4. The device resets itself after the update is accepted. The bootloader then installs the
   package, the device stays dark for about 30 s. Auto-reconnect picks it up, and the new FW
   version appears above the tabs.
5. **Abort** stops the transfer and sends ABORT to the device.


To see that the update really happened, change the version in `scripts/version.txt` of the
firmware before building the package and compare `Device FW version` before and after.

## Files

| File | Purpose |
|------|---------|
| `tb_hid_tool.py` | the tool |
| `tb_commands.json` | default commands and the placeholder frame layout |
| `requirements.txt` | Python dependencies |
| `run_tb_hid_tool.bat` | starts the tool |
| `logs/` | saved logs (ignored by git) |

## Notes

- The frame layout follows the draft of the TB transport protocol (Confluence); opcodes and
  property IDs other most of the values are a placeholders at the current moment.
