#!/usr/bin/env python3
"""
TB HID Tool - a small GUI to talk to the TB protocol HID interface (usage page 0xFF42)
of the Stealth Pro 2 over USB.

  * shows the HID devices/collections Windows sees and which one is opened
  * sends raw hex or a simple frame (report ID + opcode + payload)
  * shows everything sent (TX) and received (RX / NOTIFY) as a hex dump
  * keeps a list of default commands in tb_commands.json (next to this file)

Install:   pip install dearpygui hidapi        (NOT the package called "hid")
Run:       python tb_hid_tool.py               (or run_tb_hid_tool.bat)
"""
import argparse
import collections
import datetime
import json
import os
import queue
import re
import sys
import threading
import time
import zlib

try:
    import hid
    import dearpygui.dearpygui as dpg
except ImportError as exc:  # pragma: no cover
    print("Missing dependency: %s\n\n  pip install dearpygui hidapi\n" % exc)
    sys.exit(1)

if not hasattr(hid, "device"):
    print("Wrong 'hid' package is installed.\n\n  pip uninstall hid\n  pip install hidapi\n")
    sys.exit(1)

APP_TITLE = "TB HID Tool"
APP_DIR = os.path.dirname(os.path.abspath(__file__))
COMMANDS_FILE = os.path.join(APP_DIR, "tb_commands.json")
LOG_DIR = os.path.join(APP_DIR, "logs")

TB_USAGE_PAGE = 0xFF42
TB_VID = 0x10F5  # Turtle Beach
MAX_READ = 128
MAX_LOG_ITEMS = 1500
REFRESH_PERIOD_S = 1.5

# Firmware update protocol (matches tb_fwupd_protocol_parser.c in the firmware)
FW_REPORT_SIZE = 64             # HID report incl. the report ID byte
FW_BLOCK_SIZE = 4096            # one block = one flash sector, one ACK
FW_PACKET_DATA = 60             # stream packet = 3 byte header + 60 data bytes
FW_DEST_MASTER = 1              # destination 1 = master, 2 = slave (not implemented in firmware yet)
FW_STREAM_ID = 1
FW_FRAME_COMMAND = 0
FW_FRAME_RESPONSE = 1
FW_FRAME_STREAM = 2
FW_OP_START = 0x10              # payload: image_size u32 LE, crc32 u32 LE
FW_OP_STREAM_ACK = 0x11         # device -> host: stream_id, status (0 OK, 1 ERROR), block index u16 MSB first
FW_OP_VERIFY = 0x12
FW_OP_APPLY = 0x13
FW_OP_ABORT = 0x14
FW_OP_NAMES = {FW_OP_START: "START", FW_OP_VERIFY: "VERIFY", FW_OP_APPLY: "APPLY", FW_OP_ABORT: "ABORT"}
FW_ERROR_NAMES = {
    1: "command not allowed in the current state",
    2: "bad parameter (or destination is not the master)",
    3: "image does not fit in the FOTA partition",
    4: "flash erase/write/read failed",
    5: "image CRC32 mismatch",
    6: "image is not complete",
    7: "cannot trigger the update",
}
FW_RESPONSE_TIMEOUT_S = 3.0
FW_ACK_TIMEOUT_S = 5.0          # includes flash erase + write of one block
FW_VERIFY_TIMEOUT_S = 30.0      # the device reads the whole image back from flash

# Colours
C_TX = (120, 220, 140)
C_RX = (110, 200, 255)
C_NOTIFY = (255, 180, 90)
C_INFO = (170, 170, 170)
C_ERR = (255, 110, 110)
C_OK = (90, 235, 120)

# --------------------------------------------------------------------------------------
# Default config. The opcodes are PLACEHOLDERS until the TB protocol spec
# ("3. Protocol Structure" in Confluence) is wired in - edit them in tb_commands.json.
# --------------------------------------------------------------------------------------
DEFAULT_CONFIG = {
    "protocol": {
        "_comment": "PLACEHOLDER frame layout: [report_id_out][opcode][payload...]. Edit to match the real spec.",
        "report_id_in": "0x01",
        "report_id_out": "0x02",
        "report_id_notify": "0x03",
        "report_size": 64,
        "opcodes": [
            {"name": "SET_PROPERTY", "code": "0x01"},
            {"name": "GET_PROPERTY", "code": "0x02"},
            {"name": "NOTIFICATION", "code": "0x03"},
        ],
    },
    "commands": [
        {"group": "Link test", "name": "Echo 01..3F (63 B)",
         "hex": " ".join("%02X" % b for b in [0x02] + list(range(1, 64))),
         "note": "Firmware loopback: OUT 0x02 -> IN 0x01 with the same payload"},
        {"group": "Link test", "name": "Echo short (4 B)", "hex": "02 AA BB CC DD",
         "note": "Short echo, padded with zeros up to the report size"},
        {"group": "Protocol (placeholder)", "name": "Get property 0x0001", "hex": "02 02 01 00",
         "note": "PLACEHOLDER - GET_PROPERTY, property id 0x0001"},
        {"group": "Protocol (placeholder)", "name": "Set property 0x0001 = 1", "hex": "02 01 01 00 01",
         "note": "PLACEHOLDER - SET_PROPERTY, property id 0x0001, value 1"},
    ],
}


def load_config():
    if not os.path.exists(COMMANDS_FILE):
        save_config(DEFAULT_CONFIG)
        return json.loads(json.dumps(DEFAULT_CONFIG))
    try:
        with open(COMMANDS_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        cfg.setdefault("protocol", DEFAULT_CONFIG["protocol"])
        cfg.setdefault("commands", [])
        return cfg
    except (OSError, ValueError) as exc:
        print("Cannot read %s (%s), using defaults" % (COMMANDS_FILE, exc))
        return json.loads(json.dumps(DEFAULT_CONFIG))


def save_config(cfg):
    with open(COMMANDS_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------
def parse_hex(text):
    """'02 01 0x0A, 0b' / '0201' -> bytes. Raises ValueError with a readable message."""
    out = bytearray()
    for tok in (t for t in re.split(r"[\s,;:\-]+", text.strip()) if t):
        if tok[:2].lower() == "0x":
            tok = tok[2:]
        if not tok or not re.fullmatch(r"[0-9a-fA-F]+", tok):
            raise ValueError("bad hex value '%s'" % tok)
        if len(tok) % 2:
            tok = "0" + tok
        out += bytes.fromhex(tok)
    return bytes(out)


def to_int(text, default=0):
    try:
        return int(str(text).strip(), 0)
    except ValueError:
        return default


def hexdump(data, trim_zeros):
    note = ""
    if trim_zeros:
        n = max(len(data.rstrip(b"\x00")), 1)
        if n < len(data):
            note = "   (+%d x 00)" % (len(data) - n)
            data = data[:n]
    rows = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexs = " ".join("%02X" % b for b in chunk).ljust(47)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append("      %04X  %s  |%s|" % (off, hexs, asc))
    if note and rows:
        rows[-1] += note
    return rows


def now_str(ts=None):
    return datetime.datetime.fromtimestamp(ts or time.time()).strftime("%H:%M:%S.%f")[:-3]


def collection_tag(path):
    m = re.search(rb"[Cc]ol(\d+)", path or b"")
    return "Col%s" % m.group(1).decode() if m else "-"


# --------------------------------------------------------------------------------------
# HID link: opens one or more collections and reads them in background threads
# --------------------------------------------------------------------------------------
class Link:
    def __init__(self, event_queue):
        self.q = event_queue
        self.handles = []
        self.threads = []
        self.running = False
        self.tx_count = 0
        self.rx_count = 0

    @property
    def connected(self):
        return self.running and bool(self.handles)

    def open(self, infos):
        self.close()
        opened = []
        try:
            for info in infos:
                h = hid.device()
                h.open_path(info["path"])
                label = "%s (usage 0x%04X)" % (collection_tag(info["path"]), info["usage"])
                opened.append({"h": h, "info": info, "label": label})
        except (OSError, ValueError):
            for ent in opened:
                ent["h"].close()
            raise
        self.handles = opened
        self.running = True
        self.tx_count = self.rx_count = 0
        for idx in range(len(opened)):
            t = threading.Thread(target=self._reader, args=(idx,), daemon=True)
            t.start()
            self.threads.append(t)

    def _reader(self, idx):
        h = self.handles[idx]["h"]
        while self.running:
            try:
                data = h.read(MAX_READ, 100)
            except (OSError, ValueError) as exc:
                if self.running:
                    self.q.put(("lost", idx, str(exc)))
                return
            if data:
                self.q.put(("rx", idx, bytes(data), time.time()))

    def write(self, idx, data):
        h = self.handles[idx]["h"]
        n = h.write(data)
        if n < 0:
            raise OSError(h.error())
        self.tx_count += 1
        return n

    def close(self):
        self.running = False
        for t in self.threads:
            t.join(timeout=0.5)
        for ent in self.handles:
            try:
                ent["h"].close()
            except Exception:
                pass
        self.handles = []
        self.threads = []


def enumerate_entries():
    entries = []
    for d in hid.enumerate(0, 0):
        entries.append({
            "vid": d["vendor_id"], "pid": d["product_id"],
            "iface": d["interface_number"],
            "usage_page": d["usage_page"], "usage": d["usage"],
            "product": d.get("product_string") or "",
            "serial": d.get("serial_number") or "",
            "path": d["path"],
        })
    return entries


def is_tb(entry):
    return entry["vid"] == TB_VID and entry["usage_page"] == TB_USAGE_PAGE


# --------------------------------------------------------------------------------------
# GUI application
# --------------------------------------------------------------------------------------
class App:
    def __init__(self):
        self.cfg = load_config()
        self.evq = queue.Queue()
        self.link = Link(self.evq)
        self.dev_map = {}          # listbox string -> entry
        self.dev_sig = None
        self.selected_path = None
        self.all_paths = set()
        self.reconnect_key = None  # (vid, pid, iface, usage_page, usage, open_all)
        self.last_conn_err = ""
        self.log_items = collections.deque()
        self.log_text = []
        self.cmd_sel_ids = []
        self.cmd_selected = None
        self.echo = None           # dict(expect=bytes, deadline=float)
        self.next_refresh = 0.0
        self.next_repeat = 0.0
        self.fw = None             # running firmware update (dict) or None
        self.fw_image = None       # loaded file (dict) or None
        self.fw_ctrl_seq = 0

    # ------------------------------------------------------------------ logging
    def log(self, kind, text, extra=None, ts=None):
        color = {"TX": C_TX, "RX": C_RX, "NOTIFY": C_NOTIFY, "ERR": C_ERR,
                 "OK": C_OK}.get(kind, C_INFO)
        header = "%s  %-6s %s" % (now_str(ts), kind, text)
        lines = [header]
        if extra:
            lines += extra
        for ln in lines:
            self.log_text.append(ln)
            item = dpg.add_text(ln, parent="log_win", color=color if ln is header else
                                tuple(int(c * 0.78) for c in color))
            self.log_items.append(item)
        while len(self.log_items) > MAX_LOG_ITEMS:
            dpg.delete_item(self.log_items.popleft())
        if len(self.log_text) > 20000:
            del self.log_text[:5000]
        if dpg.get_value("autoscroll"):
            dpg.set_y_scroll("log_win", -1.0)

    def log_clear(self, *_):
        dpg.delete_item("log_win", children_only=True)
        self.log_items.clear()
        self.log_text.clear()

    def log_copy(self, *_):
        text = "\n".join(self.log_text)
        if hasattr(dpg, "set_clipboard_text"):
            dpg.set_clipboard_text(text)
            self.log("INFO", "Log copied to clipboard (%d lines)" % len(self.log_text))
        else:
            self.log_save()

    def log_save(self, *_):
        os.makedirs(LOG_DIR, exist_ok=True)
        path = os.path.join(LOG_DIR, "tb_hid_log_%s.txt" %
                            datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.log_text) + "\n")
        self.log("INFO", "Log saved: %s" % path)

    # ------------------------------------------------------------------ devices
    def refresh_devices(self, force=False):
        try:
            entries = enumerate_entries()
        except Exception as exc:
            self.log("ERR", "enumerate failed: %s" % exc)
            return
        self.all_paths = {e["path"] for e in entries}

        shown = [e for e in entries if is_tb(e)]
        shown.sort(key=lambda e: (e["pid"], e["iface"], e["path"]))
        uniq = {}
        for e in shown:  # one row per physical interface (Windows splits it into Col01/Col02)
            uniq.setdefault((e["vid"], e["pid"], e["iface"]), e)
        shown = list(uniq.values())

        sig = tuple(e["path"] for e in shown)
        if force or sig != self.dev_sig:
            self.dev_sig = sig
            self.dev_map = {}
            items = []
            for e in shown:
                s = "%s   PID %04X   interface %s" % (
                    e["product"] or "TB device", e["pid"], e["iface"])
                while s in self.dev_map:
                    s += " "
                self.dev_map[s] = e
                items.append(s)
            dpg.configure_item("devlist", items=items)
            keep = next((s for s, e in self.dev_map.items() if e["path"] == self.selected_path), None)
            if keep is None and items:
                keep = items[0]
                self.selected_path = self.dev_map[keep]["path"]
            if keep:
                dpg.set_value("devlist", keep)
        # connected device disappeared
        if self.link.connected and not any(h["info"]["path"] in self.all_paths for h in self.link.handles):
            self.log("ERR", "Device removed")
            self.disconnect(manual=False)
        # auto-reconnect
        if (not self.link.connected and self.reconnect_key and dpg.get_value("auto_reconnect")):
            vid, pid, iface, up, usage, open_all = self.reconnect_key
            cand = [e for e in entries if e["vid"] == vid and e["pid"] == pid and
                    e["iface"] == iface and e["usage_page"] == up]
            if cand:
                self.connect_entries(cand, open_all, auto=True)

    def cb_dev_pick(self, sender, app_data):
        e = self.dev_map.get(app_data)
        self.selected_path = e["path"] if e else None

    def connect_entries(self, cand, open_all, auto=False):
        sel = cand[0]
        if open_all and sel["iface"] >= 0:
            infos = [e for e in cand if e["iface"] == sel["iface"] and e["vid"] == sel["vid"]
                     and e["pid"] == sel["pid"]]
        else:
            infos = [sel]
        infos.sort(key=lambda e: e["usage"])
        try:
            self.link.open(infos)
        except (OSError, ValueError) as exc:
            msg = "Cannot open %04X:%04X if%s: %s" % (sel["vid"], sel["pid"], sel["iface"], exc)
            if msg != self.last_conn_err:
                self.log("ERR", msg)
                self.last_conn_err = msg
            return False
        self.last_conn_err = ""
        self.reconnect_key = (sel["vid"], sel["pid"], sel["iface"], sel["usage_page"], sel["usage"], open_all)
        labels = [h["label"] for h in self.link.handles]
        pref = next((l for l in labels if "0x0001" in l), labels[0])
        self.log("INFO", "%sConnected if%s '%s'" % ("Re" if auto else "", sel["iface"], sel["product"]))
        return True

    def cb_connect(self, *_):
        if self.link.connected:
            self.disconnect()
        sel = next((e for e in self.dev_map.values() if e["path"] == self.selected_path), None)
        if not sel:
            self.log("ERR", "Select a device in the list first")
            return
        entries = [e for e in enumerate_entries()
                   if e["vid"] == sel["vid"] and e["pid"] == sel["pid"]]
        entries.sort(key=lambda e: e["path"] != sel["path"])  # selected first
        self.connect_entries(entries, True)

    def disconnect(self, manual=True):
        was = self.link.connected
        self.link.close()
        if manual:
            self.reconnect_key = None
        if was:
            self.log("INFO", "Disconnected")

    def cb_disconnect(self, *_):
        self.disconnect()

    # ------------------------------------------------------------------ sending
    def send_bytes(self, data, origin=""):
        if not self.link.connected:
            self.log("ERR", "Not connected")
            return False
        if not data:
            self.log("ERR", "Nothing to send")
            return False
        if dpg.get_value("pad_on"):
            size = max(to_int(dpg.get_value("pad_size"), 64), 1)
            if len(data) < size:
                data = data + bytes(size - len(data))
        labels = [h["label"] for h in self.link.handles]
        order = list(range(len(labels)))
        pref = getattr(self, "write_idx", 0)
        if pref in order:
            order.remove(pref)
            order.insert(0, pref)
        idx, last_exc = None, None
        for i in order:
            try:
                self.link.write(i, data)
                idx = i
                self.write_idx = i
                break
            except (OSError, ValueError) as exc:
                last_exc = exc
        if idx is None:
            self.log("ERR", "write failed: %s" % last_exc)
            return False
        self.log("TX", "%s  id=0x%02X len=%d%s" % (labels[idx], data[0], len(data),
                                                   ("  [%s]" % origin) if origin else ""),
                 hexdump(data, dpg.get_value("trim")))
        return True

    def cb_send_raw(self, *_):
        try:
            data = parse_hex(dpg.get_value("hex_in"))
        except ValueError as exc:
            self.log("ERR", "Hex error: %s" % exc)
            return
        self.send_bytes(data, "raw")

    def cb_echo(self, *_):
        rid = to_int(self.cfg["protocol"].get("report_id_out", "0x02"), 2)
        size = max(to_int(dpg.get_value("pad_size"), 64), 2) if dpg.get_value("pad_on") else 64
        data = bytes([rid]) + bytes((i % 255) + 1 for i in range(size - 1))
        if self.send_bytes(data, "echo test"):
            self.echo = {"expect": data[1:], "deadline": time.time() + 1.0}

    # ------------------------------------------------------------------ frame builder
    def build_frame(self):
        p = self.cfg["protocol"]
        rid = to_int(dpg.get_value("fb_rid"), 2)
        name = dpg.get_value("fb_op")
        code = next((to_int(o["code"]) for o in p.get("opcodes", []) if o["name"] == name), None)
        if code is None:
            code = to_int(dpg.get_value("fb_op_custom"), 0)
        payload = parse_hex(dpg.get_value("fb_payload"))
        return bytes([rid, code]) + payload

    def cb_fb_changed(self, *_):
        try:
            dpg.set_value("fb_preview", "Frame: " + " ".join("%02X" % b for b in self.build_frame()))
        except ValueError as exc:
            dpg.set_value("fb_preview", "Frame: (%s)" % exc)

    def cb_fb_send(self, *_):
        try:
            self.send_bytes(self.build_frame(), "frame")
        except ValueError as exc:
            self.log("ERR", "Payload error: %s" % exc)

    def cb_fb_to_raw(self, *_):
        try:
            dpg.set_value("hex_in", " ".join("%02X" % b for b in self.build_frame()))
        except ValueError as exc:
            self.log("ERR", "Payload error: %s" % exc)

    def drag_splitters(self):
        if dpg.is_item_active("vsplit"):
            x = dpg.get_mouse_pos(local=False)[0]
            vw = dpg.get_viewport_client_width()
            dpg.configure_item("left_pane", width=int(max(220, min(x - 14, vw - 420))))
        if dpg.is_item_active("hsplit"):
            y = dpg.get_mouse_pos(local=False)[1]
            top = dpg.get_item_rect_min("send_panel")[1]
            vh = dpg.get_viewport_client_height()
            dpg.configure_item("send_panel", height=int(max(120, min(y - top - 3, vh - 200))))

    # ------------------------------------------------------------------ UI lock
    def _walk(self, item, out):
        for slot in (1, 2, 3):
            for ch in dpg.get_item_children(item, slot) or []:
                out.append(ch)
                self._walk(ch, out)

    def apply_lock(self, connected, force=False):
        if not force and getattr(self, "locked_state", None) == connected:
            return
        self.locked_state = connected
        items = []
        for root in ("send_panel", "cmd_list"):
            self._walk(root, items)
        for it in items:
            try:
                (dpg.enable_item if connected else dpg.disable_item)(it)
            except Exception:
                pass

    # ------------------------------------------------------------------ commands list
    def rebuild_commands(self):
        dpg.delete_item("cmd_list", children_only=True)
        self.cmd_sel_ids = []
        self.locked_state = None
        groups = collections.OrderedDict()
        for i, c in enumerate(self.cfg["commands"]):
            groups.setdefault(c.get("group", "General"), []).append(i)
        for g, idxs in groups.items():
            with dpg.collapsing_header(label=g, default_open=True, parent="cmd_list"):
                for i in idxs:
                    c = self.cfg["commands"][i]
                    with dpg.group(horizontal=True):
                        dpg.add_button(label="Send", width=46, callback=self.cb_cmd_send, user_data=i)
                        sid = dpg.add_selectable(label=c["name"], callback=self.cb_cmd_pick, user_data=i)
                        self.cmd_sel_ids.append((i, sid))
                        with dpg.tooltip(sid):
                            dpg.add_text(c.get("hex", ""), wrap=420)
                            if c.get("note"):
                                dpg.add_text(c["note"], color=C_INFO, wrap=420)

    def cb_cmd_pick(self, sender, app_data, user_data):
        self.cmd_selected = user_data
        for i, sid in self.cmd_sel_ids:
            dpg.set_value(sid, i == user_data)
        c = self.cfg["commands"][user_data]
        dpg.set_value("hex_in", c.get("hex", ""))

    def cb_cmd_send(self, sender, app_data, user_data):
        self.cb_cmd_pick(sender, app_data, user_data)
        c = self.cfg["commands"][user_data]
        try:
            self.send_bytes(parse_hex(c.get("hex", "")), c["name"])
        except ValueError as exc:
            self.log("ERR", "Hex error in '%s': %s" % (c["name"], exc))

    def cb_cmd_save(self, *_):
        name = dpg.get_value("save_name").strip()
        group = dpg.get_value("save_group").strip() or "General"
        hex_text = dpg.get_value("hex_in").strip()
        if not name:
            self.log("ERR", "Give the command a name first")
            return
        try:
            parse_hex(hex_text)
        except ValueError as exc:
            self.log("ERR", "Hex error: %s" % exc)
            return
        for c in self.cfg["commands"]:
            if c["name"] == name and c.get("group", "General") == group:
                c["hex"] = hex_text
                break
        else:
            self.cfg["commands"].append({"group": group, "name": name, "hex": hex_text})
        save_config(self.cfg)
        self.rebuild_commands()
        self.log("INFO", "Command '%s' saved to %s" % (name, os.path.basename(COMMANDS_FILE)))

    def cb_cmd_delete(self, *_):
        if self.cmd_selected is None or self.cmd_selected >= len(self.cfg["commands"]):
            self.log("ERR", "Pick a command in the list to delete")
            return
        c = self.cfg["commands"].pop(self.cmd_selected)
        self.cmd_selected = None
        save_config(self.cfg)
        self.rebuild_commands()
        self.log("INFO", "Command '%s' deleted" % c["name"])

    # ------------------------------------------------------------------ firmware update
    def fw_frame_control(self, opcode, payload=b""):
        seq = self.fw_ctrl_seq & 0x0F
        self.fw_ctrl_seq = (self.fw_ctrl_seq + 1) & 0x0F
        header = bytes([FW_FRAME_COMMAND << 5, (seq << 4) | (FW_DEST_MASTER << 2), 0, opcode,
                        (len(payload) >> 8) & 0x0F, len(payload) & 0xFF])
        return header + payload

    def fw_frame_stream(self, packet_seq, data):
        return bytes([(FW_FRAME_STREAM << 5) | FW_STREAM_ID, FW_DEST_MASTER, packet_seq & 0xFF]) + data

    def fw_write(self, frame):
        """One HID report: report ID + frame, zero padded to the report size. Raises OSError."""
        rid = to_int(self.cfg["protocol"].get("report_id_out", "0x02"), 2)
        report = bytes([rid]) + frame
        report += bytes(max(0, FW_REPORT_SIZE - len(report)))
        order = list(range(len(self.link.handles)))
        pref = getattr(self, "write_idx", 0)
        if pref in order:
            order.remove(pref)
            order.insert(0, pref)
        last_exc = None
        for i in order:
            try:
                self.link.write(i, report)
                self.write_idx = i
                return
            except (OSError, ValueError) as exc:
                last_exc = exc
        raise OSError(str(last_exc))

    def fw_send_control(self, opcode, payload=b"", note=""):
        frame = self.fw_frame_control(opcode, payload)
        self.fw_write(frame)
        self.log("TX", "FW %s  %s%s" % (FW_OP_NAMES.get(opcode, "0x%02X" % opcode),
                                       " ".join("%02X" % b for b in frame), ("  " + note) if note else ""))

    def fw_set_status(self, text, color=C_INFO):
        dpg.set_value("fw_status", text)
        dpg.configure_item("fw_status", color=color)

    def fw_elapsed(self):
        """Seconds since the update started (frozen after it ends)."""
        if self.fw:
            return time.time() - self.fw["t0"]
        return getattr(self, "fw_last_elapsed", 0.0)

    def fw_set_progress(self, done, total, label=None):
        self.fw_progress_state = (done, total, label)
        dpg.set_value("fw_progress", (done / total) if total else 0.0)
        text = label or ("%d / %d blocks" % (done, total))
        dpg.configure_item("fw_progress", overlay="%s   |   %.1f s" % (text, self.fw_elapsed()))

    def fw_refresh_progress(self):
        state = getattr(self, "fw_progress_state", None)
        if state:
            self.fw_set_progress(*state)

    def fw_load_file(self, path):
        """Read the file and show its size, block count and CRC32. Returns True when ready."""
        self.fw_image = None
        path = (path or "").strip().strip('"')
        if not path:
            dpg.set_value("fw_info", "No file selected")
            return False
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as exc:
            dpg.set_value("fw_info", "Cannot read file: %s" % exc)
            return False
        if not data:
            dpg.set_value("fw_info", "File is empty")
            return False
        crc = zlib.crc32(data) & 0xFFFFFFFF
        blocks = (len(data) + FW_BLOCK_SIZE - 1) // FW_BLOCK_SIZE
        self.fw_image = {"path": path, "data": data, "crc": crc, "blocks": blocks}
        dpg.set_value("fw_info", "%s   |   %d bytes   |   %d blocks of %d   |   CRC32 0x%08X" % (
            os.path.basename(path), len(data), blocks, FW_BLOCK_SIZE, crc))
        return True

    def fw_set_default_file(self):
        guess = os.path.normpath(os.path.join(APP_DIR, "..", "master", "fota_package.bin"))
        if os.path.exists(guess):
            dpg.set_value("fw_path", guess)
            self.fw_load_file(guess)

    def cb_fw_path(self, *_):
        self.fw_load_file(dpg.get_value("fw_path"))

    def cb_fw_file_picked(self, sender, app_data):
        picked = app_data.get("file_path_name", "")
        if picked and not picked.endswith(".*"):
            dpg.set_value("fw_path", picked)
            self.fw_load_file(picked)

    def cb_fw_start(self, *_):
        if self.fw:
            self.log("ERR", "FW update is already running")
            return
        if not self.link.connected:
            self.log("ERR", "Not connected")
            return
        if not self.fw_load_file(dpg.get_value("fw_path")):   # re-read: the build may have changed the file
            self.log("ERR", "FW update: choose a valid file first")
            return
        image = self.fw_image
        self.fw = {"state": "start", "wait_opcode": FW_OP_START, "block": 0, "blocks": image["blocks"],
                   "data": image["data"], "crc": image["crc"], "t0": time.time(),
                   "deadline": time.time() + FW_RESPONSE_TIMEOUT_S}
        self.fw_ctrl_seq = 0
        self.log("INFO", "FW update: %s, %d bytes, %d blocks, CRC32 0x%08X, destination master" % (
            os.path.basename(image["path"]), len(image["data"]), image["blocks"], image["crc"]))
        self.fw_set_progress(0, image["blocks"], "Starting...")
        self.fw_set_status("Update running", C_NOTIFY)
        payload = len(image["data"]).to_bytes(4, "little") + image["crc"].to_bytes(4, "little")
        try:
            self.fw_send_control(FW_OP_START, payload, "size=%d crc=0x%08X" % (len(image["data"]), image["crc"]))
        except OSError as exc:
            self.fw_fail("write failed: %s" % exc, send_abort=False)

    def cb_fw_abort(self, *_):
        if not self.fw:
            return
        self.fw_fail("aborted by user")

    def fw_fail(self, reason, send_abort=True):
        self.log("ERR", "FW update FAILED: %s" % reason)
        if self.fw and self.fw["block"] < self.fw["blocks"]:
            self.fw_set_progress(self.fw["block"], self.fw["blocks"],
                                 "FAILED at block %d / %d" % (self.fw["block"] + 1, self.fw["blocks"]))
        self.fw_set_status("FAILED: %s" % reason, C_ERR)
        if self.fw:
            self.fw_last_elapsed = time.time() - self.fw["t0"]
        self.fw = None
        if send_abort and self.link.connected:
            try:
                self.fw_send_control(FW_OP_ABORT)
            except OSError:
                pass

    def fw_send_block(self):
        fw = self.fw
        index = fw["block"]
        block = fw["data"][index * FW_BLOCK_SIZE:(index + 1) * FW_BLOCK_SIZE]
        packets = 0
        try:
            for offset in range(0, len(block), FW_PACKET_DATA):
                self.fw_write(self.fw_frame_stream(packets, block[offset:offset + FW_PACKET_DATA]))
                packets += 1
        except OSError as exc:
            self.fw_fail("write failed in block %d: %s" % (index + 1, exc), send_abort=False)
            return
        self.log("TX", "FW block %d / %d: %d bytes in %d packets, waiting for ACK" % (
            index + 1, fw["blocks"], len(block), packets))
        fw["state"] = "ack"
        fw["deadline"] = time.time() + FW_ACK_TIMEOUT_S

    def fw_on_rx(self, data, ts):
        """Returns True when the report was a firmware update frame (then it is not dumped as hex)."""
        if not self.fw or len(data) < 7:
            return False
        frame = data[1:]                                   # data[0] = report ID
        frame_type = frame[0] >> 5
        opcode = frame[3]
        if frame_type == FW_FRAME_RESPONSE and opcode in FW_OP_NAMES:
            is_error = bool(frame[0] & 0x08)
            error_code = frame[6] if is_error and len(frame) > 6 else 0
            self.fw_on_response(opcode, is_error, error_code, ts)
            return True
        if frame_type == FW_FRAME_COMMAND and opcode == FW_OP_STREAM_ACK and len(frame) >= 10:
            self.fw_on_stream_ack(frame[7], (frame[8] << 8) | frame[9], ts)
            return True
        return False

    def fw_on_response(self, opcode, is_error, error_code, ts):
        fw = self.fw
        name = FW_OP_NAMES[opcode]
        if opcode != fw["wait_opcode"]:
            self.log("INFO", "FW: unexpected %s response ignored" % name, ts=ts)
            return
        if is_error:
            self.log("RX", "FW %s response: ERROR %d" % (name, error_code), ts=ts)
            self.fw_fail("%s refused by the device: %s" % (name, FW_ERROR_NAMES.get(error_code, "error %d" % error_code)),
                         send_abort=False)
            return
        self.log("RX", "FW %s response: OK" % name, ts=ts)
        if opcode == FW_OP_START:
            fw["state"] = "send"
        elif opcode == FW_OP_VERIFY:
            self.log("OK", "Device verified the image CRC32 in flash")
            fw["wait_opcode"] = FW_OP_APPLY
            fw["state"] = "apply"
            fw["deadline"] = time.time() + FW_RESPONSE_TIMEOUT_S
            self.fw_set_progress(fw["blocks"], fw["blocks"], "Applying...")
            try:
                self.fw_send_control(FW_OP_APPLY)
            except OSError as exc:
                self.fw_fail("write failed: %s" % exc, send_abort=False)
        elif opcode == FW_OP_APPLY:
            elapsed = max(time.time() - fw["t0"], 0.001)
            self.fw_last_elapsed = elapsed
            self.log("OK", "FW update done: %d bytes in %.1f s (%.1f KB/s). The device has set the update flag." % (
                len(fw["data"]), elapsed, len(fw["data"]) / 1024.0 / elapsed))
            self.fw = None
            self.fw_set_progress(fw["blocks"], fw["blocks"], "Done")
            self.fw_set_status("Done: the device accepted the update and resets", C_OK)

    def fw_on_stream_ack(self, ack_status, block_index, ts):
        fw = self.fw
        if fw["state"] != "ack":
            self.log("INFO", "FW: unexpected block ACK ignored (block %d)" % block_index, ts=ts)
            return
        if ack_status != 0:
            self.log("RX", "FW block %d / %d: ACK ERROR (flash write failed)" % (block_index + 1, fw["blocks"]), ts=ts)
            self.fw_fail("the device could not write block %d" % (block_index + 1), send_abort=False)
            return
        if block_index != fw["block"]:
            self.fw_fail("ACK for block %d, expected %d" % (block_index, fw["block"]))
            return
        fw["block"] += 1
        self.log("RX", "FW block %d / %d written (ACK OK)" % (fw["block"], fw["blocks"]), ts=ts)
        self.fw_set_progress(fw["block"], fw["blocks"])
        if fw["block"] < fw["blocks"]:
            fw["state"] = "send"
            return
        fw["state"] = "verify"
        fw["wait_opcode"] = FW_OP_VERIFY
        fw["deadline"] = time.time() + FW_VERIFY_TIMEOUT_S
        self.fw_set_progress(fw["blocks"], fw["blocks"], "Verifying...")
        try:
            self.fw_send_control(FW_OP_VERIFY)
        except OSError as exc:
            self.fw_fail("write failed: %s" % exc, send_abort=False)

    def fw_tick(self):
        fw = self.fw
        if not fw:
            return
        if not self.link.connected:
            self.fw_fail("device disconnected", send_abort=False)
            return
        if fw["state"] == "send":
            self.fw_send_block()
        elif time.time() > fw["deadline"]:
            what = {"start": "the START response", "ack": "the ACK of block %d" % (fw["block"] + 1),
                    "verify": "the VERIFY response", "apply": "the APPLY response"}.get(fw["state"], fw["state"])
            self.fw_fail("timeout waiting for %s" % what)

    # ------------------------------------------------------------------ events
    def on_rx(self, ev):
        _, idx, data, ts = ev
        try:
            label = self.link.handles[idx]["label"]
        except IndexError:
            return
        self.link.rx_count += 1
        if self.fw_on_rx(data, ts):
            return
        p = self.cfg["protocol"]
        rid = data[0]
        notify = rid == to_int(p.get("report_id_notify", "0x03"), 3)
        kind = "NOTIFY" if notify else "RX"
        self.log(kind, "%s  id=0x%02X len=%d" % (label, rid, len(data)),
                 hexdump(data, dpg.get_value("trim")), ts=ts)
        if self.echo and rid == to_int(p.get("report_id_in", "0x01"), 1):
            n = len(self.echo["expect"])
            if data[1:1 + n] == self.echo["expect"]:
                self.log("OK", "Echo test PASS (%d bytes returned unchanged)" % n)
            else:
                self.log("ERR", "Echo test FAIL: reply differs from what was sent")
            self.echo = None

    def on_lost(self, ev):
        if self.link.connected:
            self.log("ERR", "Read failed: %s" % ev[2])
            self.disconnect(manual=False)

    def tick(self):
        while True:
            try:
                ev = self.evq.get_nowait()
            except queue.Empty:
                break
            if ev[0] == "rx":
                self.on_rx(ev)
            elif ev[0] == "lost":
                self.on_lost(ev)
        self.fw_tick()
        if self.fw:
            self.fw_refresh_progress()
        now = time.time()
        if self.echo and now > self.echo["deadline"]:
            self.log("ERR", "Echo test FAIL: no reply within 1 s")
            self.echo = None
        if dpg.get_value("repeat_on") and self.link.connected and now >= self.next_repeat:
            self.next_repeat = now + max(to_int(dpg.get_value("repeat_ms"), 500), 10) / 1000.0
            self.cb_send_raw()
        if time.monotonic() >= self.next_refresh:
            self.next_refresh = time.monotonic() + REFRESH_PERIOD_S
            self.refresh_devices()
        self.apply_lock(self.link.connected)
        self.drag_splitters()
        # status + byte counter
        if self.link.connected:
            h0 = self.link.handles[0]["info"]
            dpg.set_value("status", "Connected: %s (PID %04X)   |   Sent: %d packets   Received: %d packets" % (
                h0["product"] or "TB device", h0["pid"], self.link.tx_count, self.link.rx_count))
            dpg.configure_item("status", color=C_OK)
        else:
            dpg.set_value("status", "Not connected - select a TB device on the left and press Connect")
            dpg.configure_item("status", color=C_ERR)
        try:
            n = len(parse_hex(dpg.get_value("hex_in")))
            size = to_int(dpg.get_value("pad_size"), 64)
            pad = " (padded to %d)" % size if dpg.get_value("pad_on") and n < size else ""
            dpg.set_value("hex_info", "%d byte(s)%s" % (n, pad))
        except ValueError as exc:
            dpg.set_value("hex_info", "invalid hex: %s" % exc)

    # ------------------------------------------------------------------ UI
    def build(self):
        dpg.create_context()
        mono = None
        with dpg.font_registry():
            for path, size, which in (("C:/Windows/Fonts/segoeui.ttf", 17, "ui"),
                                      ("C:/Windows/Fonts/consola.ttf", 16, "mono")):
                if os.path.exists(path):
                    f = dpg.add_font(path, size)
                    if which == "ui":
                        dpg.bind_font(f)
                    else:
                        mono = f

        with dpg.theme() as global_theme:
            with dpg.theme_component(dpg.mvAll):
                dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 4)
                dpg.add_theme_style(dpg.mvStyleVar_ChildRounding, 4)
                dpg.add_theme_style(dpg.mvStyleVar_WindowPadding, 10, 10)
                dpg.add_theme_style(dpg.mvStyleVar_FramePadding, 8, 5)
                dpg.add_theme_style(dpg.mvStyleVar_ItemSpacing, 8, 7)
        dpg.bind_theme(global_theme)

        def color_theme(rgb):
            with dpg.theme() as t:
                with dpg.theme_component(dpg.mvButton):
                    dpg.add_theme_color(dpg.mvThemeCol_Button, rgb)
                    dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, tuple(min(255, c + 25) for c in rgb))
                    dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, tuple(min(255, c + 45) for c in rgb))
            return t

        green, red, blue = color_theme((30, 130, 70)), color_theme((150, 50, 50)), color_theme((40, 95, 160))

        with dpg.theme() as split_theme:
            with dpg.theme_component(dpg.mvButton):
                dpg.add_theme_color(dpg.mvThemeCol_Button, (60, 60, 66))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (90, 130, 190))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (90, 130, 190))
                dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 2)
        p = self.cfg["protocol"]
        op_names = [o["name"] for o in p.get("opcodes", [])] + ["(custom)"]

        with dpg.file_dialog(directory_selector=False, show=False, callback=self.cb_fw_file_picked,
                             tag="fw_file_dialog", width=720, height=420, modal=True):
            dpg.add_file_extension(".bin", color=(120, 220, 140))
            dpg.add_file_extension(".*")

        with dpg.window(tag="main"):
            with dpg.group(horizontal=True):
                # -------- left: devices + commands
                with dpg.child_window(tag="left_pane", width=430, border=False):
                    dpg.add_text("Devices", color=(255, 210, 120))
                    dpg.add_button(label="Refresh", callback=lambda *_: self.refresh_devices(True))
                    dpg.add_listbox(items=[], tag="devlist", num_items=8, width=-1, callback=self.cb_dev_pick)
                    with dpg.group(horizontal=True):
                        b1 = dpg.add_button(label="Connect", width=100, callback=self.cb_connect)
                        b2 = dpg.add_button(label="Disconnect", width=100, callback=self.cb_disconnect)
                        dpg.bind_item_theme(b1, green)
                        dpg.bind_item_theme(b2, red)
                    dpg.add_checkbox(label="Auto-reconnect", tag="auto_reconnect", default_value=True)
                    dpg.add_separator()
                    dpg.add_text("Default commands  (click = load, Send = send)", color=(255, 210, 120))
                    with dpg.child_window(tag="cmd_list", height=-1, border=True):
                        pass

                vs = dpg.add_button(tag="vsplit", label="", width=6, height=-1)
                dpg.bind_item_theme(vs, split_theme)
                # -------- right: status, send, log
                with dpg.child_window(width=-1, border=False):
                    dpg.add_text("Not connected", tag="status")
                    with dpg.child_window(tag="send_panel", height=270, border=True):
                        with dpg.group(horizontal=True):
                            dpg.add_checkbox(label="Pad with zeros to", tag="pad_on", default_value=True)
                            dpg.add_input_int(tag="pad_size", default_value=int(p.get("report_size", 64)),
                                              width=110, min_value=1, max_value=512, min_clamped=True)
                            dpg.add_text("bytes")
                        with dpg.tab_bar():
                            with dpg.tab(label="Raw hex"):
                                dpg.add_input_text(tag="hex_in", width=-1, hint="02 01 02 03 ...  (first byte = report ID)",
                                                   on_enter=True, callback=self.cb_send_raw)
                                dpg.add_text("0 byte(s)", tag="hex_info", color=C_INFO)
                                with dpg.group(horizontal=True):
                                    sb = dpg.add_button(label="Send", width=90, callback=self.cb_send_raw)
                                    dpg.bind_item_theme(sb, green)
                                    eb = dpg.add_button(label="Echo test", callback=self.cb_echo)
                                    dpg.bind_item_theme(eb, blue)
                                    with dpg.tooltip(eb):
                                        dpg.add_text("Sends OUT 0x02 + counter bytes and checks that the\n"
                                                     "firmware returns the same payload as IN 0x01", wrap=380)
                                    dpg.add_checkbox(label="Repeat every", tag="repeat_on")
                                    dpg.add_input_int(tag="repeat_ms", default_value=500, width=110, step=100,
                                                      min_value=10, min_clamped=True)
                                    dpg.add_text("ms")
                            with dpg.tab(label="Frame builder"):
                                dpg.add_text("PLACEHOLDER layout: report ID + opcode + payload "
                                             "(edit opcodes in tb_commands.json)", color=C_NOTIFY)
                                with dpg.group(horizontal=True):
                                    dpg.add_text("Report ID")
                                    dpg.add_input_text(tag="fb_rid", width=60, default_value=p.get("report_id_out", "0x02"),
                                                       callback=self.cb_fb_changed)
                                    dpg.add_text("Opcode")
                                    dpg.add_combo(items=op_names, tag="fb_op", width=170, default_value=op_names[0],
                                                  callback=self.cb_fb_changed)
                                    dpg.add_input_text(tag="fb_op_custom", width=60, hint="0x..",
                                                       callback=self.cb_fb_changed)
                                dpg.add_input_text(tag="fb_payload", width=-1, hint="payload hex, e.g. 01 00 05",
                                                   callback=self.cb_fb_changed)
                                dpg.add_text("Frame:", tag="fb_preview", color=C_INFO)
                                with dpg.group(horizontal=True):
                                    fs = dpg.add_button(label="Send frame", width=110, callback=self.cb_fb_send)
                                    dpg.bind_item_theme(fs, green)
                                    dpg.add_button(label="Copy to Raw hex", callback=self.cb_fb_to_raw)
                            with dpg.tab(label="Firmware update"):
                                with dpg.group(horizontal=True):
                                    dpg.add_input_text(tag="fw_path", width=-110, hint="path to fota_package.bin",
                                                       on_enter=True, callback=self.cb_fw_path)
                                    dpg.add_button(label="Browse...", width=100,
                                                   callback=lambda *_: dpg.show_item("fw_file_dialog"))
                                dpg.add_text("No file selected", tag="fw_info", color=C_INFO)
                                with dpg.group(horizontal=True):
                                    fw_start = dpg.add_button(label="Start update", width=130, callback=self.cb_fw_start)
                                    dpg.bind_item_theme(fw_start, green)
                                    fw_abort = dpg.add_button(label="Abort", width=90, callback=self.cb_fw_abort)
                                    dpg.bind_item_theme(fw_abort, red)
                                dpg.add_progress_bar(tag="fw_progress", width=-1, height=26, overlay="Idle")
                                dpg.add_text("", tag="fw_status", color=C_INFO)
                    hs = dpg.add_button(tag="hsplit", label="", width=-1, height=6)
                    dpg.bind_item_theme(hs, split_theme)
                    with dpg.group(horizontal=True):
                        dpg.add_text("Log", color=(255, 210, 120))
                        dpg.add_checkbox(label="Auto-scroll", tag="autoscroll", default_value=True)
                        dpg.add_checkbox(label="Trim trailing zeros", tag="trim", default_value=True)
                        dpg.add_button(label="Clear", callback=self.log_clear)
                        dpg.add_button(label="Copy", callback=self.log_copy)
                        dpg.add_button(label="Save to file", callback=self.log_save)
                    with dpg.child_window(tag="log_win", height=-1, border=True):
                        pass
        if mono:
            dpg.bind_item_font("log_win", mono)

        self.rebuild_commands()
        self.fw_set_default_file()
        self.cb_fb_changed()
        self.apply_lock(False, force=True)
        dpg.create_viewport(title=APP_TITLE, width=1240, height=780, min_width=980, min_height=600)
        dpg.setup_dearpygui()
        dpg.set_primary_window("main", True)
        dpg.show_viewport()
        self.log("INFO", "%s ready. Only Turtle Beach devices with the TB protocol interface (usage page 0xFF42) are listed." % APP_TITLE)

    def demo_log(self):
        self.log("INFO", "--- demo lines, not from a device ---")
        data = bytes([0x02] + list(range(1, 64)))
        self.log("TX", "Col01 (usage 0x0001)  id=0x02 len=64  [Echo 01..3F]", hexdump(data, True))
        self.log("RX", "Col01 (usage 0x0001)  id=0x01 len=64", hexdump(bytes([1]) + data[1:], True))
        self.log("OK", "Echo test PASS (63 bytes returned unchanged)")
        self.log("NOTIFY", "Col02 (usage 0x0002)  id=0x03 len=64", hexdump(bytes([3, 0x10, 0x01, 0x55]) + bytes(60), True))
        self.log("ERR", "write failed via Col02 (usage 0x0002): example error")

    def shutdown(self):
        self.link.close()
        dpg.destroy_context()


def main():
    ap = argparse.ArgumentParser(description=APP_TITLE)
    ap.add_argument("--shot", metavar="PNG", help="save a screenshot after a few frames and exit")
    ap.add_argument("--demo", action="store_true", help="add sample log lines (for screenshots)")
    args = ap.parse_args()

    app = App()
    app.build()
    if args.demo:
        app.demo_log()
    frame = 0
    while dpg.is_dearpygui_running():
        app.tick()
        dpg.render_dearpygui_frame()
        frame += 1
        if args.shot:
            if frame == 25:
                dpg.output_frame_buffer(args.shot)
            if frame == 40:
                break
    app.shutdown()


if __name__ == "__main__":
    main()
