# TB HID Tool

A small desktop tool (Dear PyGui + hidapi) to talk to the TB protocol HID interface
of the Turtle Beach Stealth Pro II over USB. It is a development tool: send raw frames to the
master or the slave chip, read FW versions and update the firmware of either chip (POC).

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
2. On connect the tool sends GET_PROPERTY (FW version) to the master and shows it above the
   tabs: `Device FW version: 1.31.276.0`. The default commands `Get FW version` and
   `Get slave FW version` repeat the request for the master / the slave.
3. Send frames from the tabs:
   - **Raw hex** - first byte is the report ID, padded with zeros to the report size (64).
     **Target chip** (Master / Slave) sets the destination of the frame. **Send** and **Clear**
     are in one row, below them the repeat settings.
   - **Firmware update** - see below.
4. The log shows TX / RX / NOTIFY with a hex dump. Lines are tagged `[TB_MASTER]` / `[TB_SLAVE]`.

### Default commands

The list on the left comes from `tb_commands.json` (next to the script). Click an item to load
it into Raw hex, **Send** sends it. Add your own with the save fields.

- `"action": "fw_version"` makes an item send the FW version request instead of raw hex;
  `"dest"` (`master` / `slave`) selects the chip.
- Group **Link test**: `Ping master`, `Ping slave` - PING (opcode 0x04), the device echoes the
  payload. Checks the USB link and the master-slave co-sys link.

If `tb_commands.json` is missing or broken, the tool logs an error, starts with an empty list
and does not overwrite the file when saving.

## Firmware update (POC)

Updates the master or the slave over the dedicated USB HID interface. Slave frames are
forwarded by the master over the co-sys UART link.

1. Build the firmware of Stealth Pro II (master and slave). The WSL build also creates
   `fota_package.bin` (`wsl_make_fota_package.sh`) and copies it to the Windows artifacts folder.
2. Open the **Firmware update** tab, select **Master** or **Slave**, pick the file
   (default `..\master\fota_package.bin` / `..\slave\fota_package.bin`).
   The tool shows size, block count and CRC32.
3. Press **Start update**. The image is sent in 1 KB blocks; the device acknowledges each block
   and the tool sends the next one. The progress bar shows `block N / M` and the elapsed time.
4. On START both chips switch the BT radio off, so the headset can be connected during the
   update. When the update finishes (or fails / is aborted) both chips reboot.
   The bootloader then installs the package, the device stays dark for about 30 s.
   Auto-reconnect picks it up, and the new FW version appears above the tabs.
5. **Abort** stops the transfer and sends ABORT to the device.

Typical time: master about 73 s, slave about 95 s (image ~1.5 MB).
After APPLY of a slave update the tool shows `Read failed` - expected, the master reboots.
Master and slave must run matching firmware (the ACK format counts 1 KB blocks).

To see that the update really happened, change the version in `scripts/version.txt` of the
firmware before building the package and compare the version (`Get FW version` /
`Get slave FW version`) before and after.

## Files

| File | Purpose |
|------|---------|
| `tb_hid_tool.py` | the tool |
| `tb_commands.json` | protocol section (report ids, size) and default commands |
| `requirements.txt` | Python dependencies |
| `run_tb_hid_tool.bat` | starts the tool |
| `logs/` | saved logs (ignored by git) |

## Notes

- The frame layout follows the TB transport protocol (Confluence). Some property IDs and
  commands are still placeholders.
