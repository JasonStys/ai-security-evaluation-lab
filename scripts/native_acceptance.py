"""Real frozen widget/core/history/export and honest failure-evidence acceptance. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: capture — line 120
# parameter: target — line 120
# parameter: window — line 120
# variable: load — line 126
# variable: gdi — line 127
# variable: user — line 127
# variable: pointer — line 128
# variable: arguments — line 129
# variable: library — line 129
# variable: name — line 129
# variable: result — line 129
# variable: function — line 155
# attribute: argtypes — line 156
# attribute: restype — line 156
# variable: handle — line 159
# variable: rectangle — line 160
# variable: height — line 163
# variable: width — line 163
# variable: source — line 166
# variable: destination — line 167
# variable: bitmap — line 168
# variable: previous — line 169
# variable: pixels — line 174
# variable: header — line 175
# variable: raw — line 193
# variable: scanlines — line 194
# variable: row — line 195
# variable: column — line 197
# variable: offset — line 198
# definition: chunk — line 201
# parameter: data — line 201
# parameter: name — line 201
# definition: oracle — line 223
# parameter: files — line 223
# parameter: index — line 223
# variable: value — line 226
# variable: row — line 228
# variable: value — line 232
# variable: row — line 233
# variable: value — line 236
# variable: danger — line 239
# variable: row — line 240
# variable: benign — line 242
# variable: row — line 242
# variable: row — line 246
# variable: row — line 248
# variable: rows — line 251
# variable: line — line 252
# variable: row — line 254
# variable: row — line 256
# definition: exercise — line 262
# parameter: output — line 262
# parameter: reopen — line 262
# parameter: window — line 262
# variable: deadline — line 265
# variable: expected — line 266
# variable: receipt — line 267
# definition: persist — line 285
# definition: finish — line 291
# parameter: failed — line 291
# attribute: acceptance_result — line 293
# variable: name — line 298
# variable: raw — line 298
# variable: row — line 300
# definition: checked — line 305
# parameter: callback — line 305
# definition: wait — line 313
# parameter: callback — line 313
# definition: layout — line 323
# variable: original — line 325
# variable: button — line 339
# definition: rejected — line 362
# definition: export_and_reject — line 369
# variable: parent — line 373
# variable: original — line 375
# variable: exported — line 378
# variable: path — line 379
# variable: bad — line 381
# variable: rows — line 382
# variable: line — line 384
# variable: row — line 389
# definition: completed — line 399
# parameter: index — line 399
# variable: files — line 405
# definition: input_layout — line 435
# variable: widgets — line 440
# variable: name — line 441
# variable: widget — line 443
# definition: start — line 459
# parameter: index — line 459
# variable: imported — line 466
# definition: begin — line 475
# variable: identity — line 479
# END CODE MAP

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import struct
import sys
import time
import zlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aisec import desktop_project as project
from aisec.desktop_io import json_value

if TYPE_CHECKING:
    from tkinter import ttk

    from aisec.desktop import Workbench


def capture(window: Workbench, target: Path) -> None:
    """Capture only this owned synthetic Tk window via PrintWindow, never the user's whole desktop."""
    if sys.platform != "win32":
        raise OSError("native screenshot acceptance targets Windows")
    from ctypes import wintypes

    load = ctypes.WinDLL
    user, gdi = load("user32", use_last_error=True), load("gdi32", use_last_error=True)
    pointer = ctypes.c_void_p
    for library, name, arguments, result in [
        (user, "GetAncestor", [pointer, ctypes.c_uint], pointer),
        (user, "GetWindowDC", [pointer], pointer),
        (gdi, "CreateCompatibleDC", [pointer], pointer),
        (gdi, "CreateCompatibleBitmap", [pointer, ctypes.c_int, ctypes.c_int], pointer),
        (gdi, "SelectObject", [pointer, pointer], pointer),
        (gdi, "DeleteObject", [pointer], ctypes.c_int),
        (gdi, "DeleteDC", [pointer], ctypes.c_int),
        (user, "ReleaseDC", [pointer, pointer], ctypes.c_int),
        (user, "PrintWindow", [pointer, pointer, ctypes.c_uint], ctypes.c_int),
        (user, "GetWindowRect", [pointer, ctypes.POINTER(wintypes.RECT)], ctypes.c_int),
        (
            gdi,
            "GetDIBits",
            [
                pointer,
                pointer,
                ctypes.c_uint,
                ctypes.c_uint,
                pointer,
                pointer,
                ctypes.c_uint,
            ],
            ctypes.c_int,
        ),
    ]:
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
    # Flush this owned native window's pending control messages before reading its pixels.
    window.root.update()
    handle = user.GetAncestor(window.root.winfo_id(), 2)
    rectangle = wintypes.RECT()
    if not user.GetWindowRect(handle, ctypes.byref(rectangle)):
        raise OSError("owned window bounds unavailable")
    width, height = rectangle.right - rectangle.left, rectangle.bottom - rectangle.top
    if not 1 <= width <= 4096 or not 1 <= height <= 4096:
        raise OSError("owned screenshot outside bounded dimensions")
    source = user.GetWindowDC(handle)
    destination = gdi.CreateCompatibleDC(source)
    bitmap = gdi.CreateCompatibleBitmap(source, width, height)
    previous = gdi.SelectObject(destination, bitmap)
    try:
        if not user.PrintWindow(handle, destination, 2):
            raise OSError("owned window rendering unavailable")
        gdi.SelectObject(destination, previous)
        pixels = ctypes.create_string_buffer(width * height * 4)
        header = ctypes.create_string_buffer(
            struct.pack(
                "<IiiHHIIiiII",
                40,
                width,
                -height,
                1,
                32,
                0,
                width * height * 4,
                0,
                0,
                0,
                0,
            )
        )
        if gdi.GetDIBits(source, bitmap, 0, height, pixels, header, 0) != height:
            raise OSError("owned screenshot pixels incomplete")
        raw = pixels.raw
        scanlines = bytearray()
        for row in range(height):
            scanlines.append(0)
            for column in range(width):
                offset = (row * width + column) * 4
                scanlines.extend((raw[offset + 2], raw[offset + 1], raw[offset]))

        def chunk(name: bytes, data: bytes) -> bytes:
            """Encode a bounded standard PNG chunk with its actual CRC."""
            return (
                struct.pack(">I", len(data))
                + name
                + data
                + struct.pack(">I", zlib.crc32(name + data))
            )

        target.write_bytes(
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(scanlines)))
            + chunk(b"IEND", b"")
        )
    finally:
        gdi.SelectObject(destination, previous)
        gdi.DeleteObject(bitmap)
        gdi.DeleteDC(destination)
        user.ReleaseDC(handle, source)


def oracle(index: int, files: dict[str, bytes]) -> None:
    """Require literal independent domain outcomes, not merely a normal process exit."""
    if index == 0:
        value = json_value(files["evaluation.json"])
        assert len(value["cases"]) == 42 and all(
            row["oracle_match"] for row in value["cases"]
        )
        assert value["mode"] == "synthetic-replay"
    elif index == 1:
        value = json_value(files["evaluation.json"])
        assert sum(not row["oracle_match"] for row in value["cases"]) == 2
        assert value["mode"] == "offline-snapshot"
    elif index in (2, 3):
        value = json_value(files["comparison.json"])
        assert len(value["review_queue"]) == 2
        if index == 2:
            danger = next(
                row for row in value["cases"] if row["id"] == "direct-override"
            )
            benign = next(row for row in value["cases"] if row["id"] == "benign-read")
            assert "UNSAFE_ALLOW_INCREASE" in danger["changes"]
            assert "BENIGN_TOOL_COMPLETION_REGRESSION" in benign["changes"]
        else:
            assert sum(row["paired_observed"] for row in value["cases"]) == 40
            assert {
                row["id"] for row in value["cases"] if not row["paired_observed"]
            } == {"direct-override", "benign-read"}
    else:
        rows = [
            json.loads(line) for line in files["snapshot-template.jsonl"].splitlines()
        ]
        assert len(rows) == 42 and all("response" in row for row in rows)
        assert all(
            "response" not in row for row in json_value(files["result.json"])["records"]
        )
    # The ordinary evaluation/comparison reports contain only metadata; the explicitly selected
    # template intentionally retains raw responses, and is never mislabeled as an evaluation.


def exercise(window: Workbench, output: Path, reopen: bool) -> None:
    """Drive the SAME real widgets/worker/core/SQLite; retain failed receipts, never retry or use a normal profile."""
    output.mkdir(mode=0o700)
    deadline = time.monotonic() + 55
    expected = len(project.SCENARIOS)
    receipt: dict[str, Any] = {
        "schema": 1,
        "product": project.PRODUCT,
        "version": project.VERSION,
        "source": window.identity.get("source"),
        "source_dirty": window.identity.get("source_dirty"),
        "python_version": sys.version.split()[0],
        "python_dll_sha256": window.identity.get("python_dll_sha256"),
        "pid": os.getpid(),
        "parent_pid": os.getppid(),
        "synthetic": True,
        "reopen": reopen,
        "passed": False,
        "steps": [],
        "tcl_version": str(window.root.tk.call("info", "patchlevel")),
        "tk_version": str(window.root.tk.call("package", "require", "Tk")),
    }

    def persist() -> None:
        """Save bounded synthetic aggregate facts without original input paths, secrets or private stores."""
        (output / "acceptance.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )

    def finish(failed: bool = False) -> None:
        """Keep each exact retained file fingerprint and request only normal application shutdown."""
        window.acceptance_result = not failed
        receipt["passed"] = not failed
        receipt["bundles"] = {
            str(row["id"]): {
                name: hashlib.sha256(raw).hexdigest()
                for name, raw in window.state.files(row["id"]).items()
            }
            for row in window.state.history()
        }
        persist()
        window.exit()

    def checked(callback: Any) -> None:
        """An oracle failure remains a failed receipt and never silently re-runs the app or clears saved history."""
        try:
            callback()
        except Exception:
            receipt["failure_stage"] = callback.__name__
            finish(True)

    def wait(callback: Any) -> None:
        """Poll only this actual owned worker under a fixed deadline, allowing normal Tk mainloop work."""
        if time.monotonic() > deadline:
            receipt["failure_stage"] = "owned-operation-deadline"
            finish(True)
        elif window.busy:
            window.root.after(60, lambda: wait(callback))
        else:
            checked(callback)

    def layout() -> None:
        """Require all lifecycle controls and full long status at the actual supported minimum viewport."""
        original = window.status.get()
        window.root.geometry("980x700")
        window.status.set(
            original
            + " Synthetic long-message layout check: existing evidence remains available and Exit waits for the owned operation."
        )
        window.root.update()
        assert (
            int(window.status_label.cget("wraplength"))
            <= window.status_label.winfo_width()
        )
        assert (
            window.status_label.winfo_height() >= window.status_label.winfo_reqheight()
        )
        for button in window.footer_buttons.values():
            assert button.winfo_width() >= button.winfo_reqwidth()
            assert button.winfo_rootx() >= window.root.winfo_rootx()
            assert (
                button.winfo_rootx() + button.winfo_width()
                <= window.root.winfo_rootx() + window.root.winfo_width()
            )
            assert (
                button.winfo_rooty() + button.winfo_height()
                <= window.root.winfo_rooty() + window.root.winfo_height()
            )
        receipt["layout"] = {
            "root": [window.root.winfo_width(), window.root.winfo_height()],
            "allLifecycleControlsVisible": True,
            "longStatusFullyWrapped": True,
        }
        receipt["steps"].append(
            "real-minimum-width-long-status-all-lifecycle-controls-visible"
        )
        window.status.set(original)
        window.root.geometry("1260x860")
        window.root.update()

    def rejected() -> None:
        """The deliberate invalid source input cannot add or overwrite a previously retained analysis."""
        assert len(window.state.history()) == expected
        assert "rejected" in window.status.get().lower()
        receipt["steps"].append("actual-invalid-input-retains-original-history")
        finish()

    def export_and_reject() -> None:
        """Invoke the real Export handler with only a controlled OS file-picker response, then reject actual bad data."""
        from unittest.mock import patch

        parent = output / "private-export"
        parent.mkdir()
        original = window.state.files(window.selected_run)
        with patch("aisec.desktop.filedialog.askdirectory", return_value=str(parent)):
            window.export_button.invoke()
        exported = next(parent.iterdir())
        assert {path.name: path.read_bytes() for path in exported.iterdir()} == original
        receipt["steps"].append("actual-widget-exact-export")
        bad = output / "changed-context.jsonl"
        rows = [
            json.loads(line)
            for line in (project.ROOT / "examples/desktop/baseline.jsonl")
            .read_bytes()
            .splitlines()
        ]
        rows[0]["case_digest"] = "0" * 64
        bad.write_bytes(b"\n".join(json.dumps(row).encode() for row in rows) + b"\n")
        window.mode.set(project.MODES[1])
        window.values["baseline"].set(
            str(project.ROOT / "examples/desktop/baseline.jsonl")
        )
        window.values["candidate"].set(str(bad))
        window.authorized.set(True)
        window.run_button.invoke()
        wait(rejected)

    def completed(index: int) -> None:
        """Check independent domain oracles against actual saved bytes and capture only this owned synthetic window."""
        assert (
            len(window.state.history()) == index + 1
            and window.selected_run == index + 1
        )
        files = window.state.files(index + 1)
        oracle(index, files)
        if index == 0:
            layout()
        if index in (0, 2):
            window.view.set("Original case decisions" if index == 0 else "Review queue")
            window.search.set("direct-override")
            window.render()
            assert len(window.table.get_children()) == 1
            window.table.selection_set("0")
            window.inspect()
            window.root.update()
            assert (
                json.loads(window.details.get("1.0", "end"))["id"] == "direct-override"
            )
            capture(
                window,
                output
                / (
                    "selected-evidence.png"
                    if index == 0
                    else "owner-unknown-review.png"
                ),
            )
        receipt["steps"].append("actual-core-scenario-" + str(index + 1))
        if index + 1 == expected:
            export_and_reject()
        else:
            start(index + 1)

    def input_layout() -> None:
        """At minimum size, every active real parameter/chooser and Run control remains fully reachable."""
        window.root.geometry("980x700")
        window.tabs.tk.call(str(window.tabs), "select", str(window.inputs_page))
        window.root.update()
        widgets: list[ttk.Widget] = [window.run_button]
        for name in project.ACTIVE_FIELDS[window.mode.get()]:
            widgets.extend(window.field_widgets[name])
        for widget in widgets:
            assert widget.winfo_ismapped()
            assert widget.winfo_rootx() >= window.root.winfo_rootx()
            assert widget.winfo_rooty() >= window.root.winfo_rooty()
            assert (
                widget.winfo_rootx() + widget.winfo_width()
                <= window.root.winfo_rootx() + window.root.winfo_width()
            )
            assert (
                widget.winfo_rooty() + widget.winfo_height()
                <= window.root.winfo_rooty() + window.root.winfo_height()
            )
        receipt["steps"].append("actual-minimum-width-active-inputs-and-run-visible")
        window.root.geometry("1260x860")
        window.root.update()

    def start(index: int) -> None:
        """Prepared cases only populate ordinary controls; external source selection and explicit Run are real."""
        window.prepared.set(project.SCENARIOS[index])
        window.load_prepared()
        assert not window.authorized.get()
        input_layout()
        if index == 0:
            imported = output / "selected-external-cases.jsonl"
            imported.write_bytes((project.ROOT / "data/cases.jsonl").read_bytes())
            window.values["cases"].set(str(imported))
            assert not window.authorized.get()
            receipt["steps"].append("actual-user-selected-external-input")
        window.authorized.set(True)
        window.run_button.invoke()
        wait(lambda: completed(index))

    def begin() -> None:
        """A second real process opens every prior exact bundle without recalculating it."""
        if reopen:
            assert len(window.state.history()) == expected
            for identity in range(1, expected + 1):
                window.history_table.selection_set(str(identity))
                window.open_button.invoke()
                assert window.selected_run == identity
                oracle(identity - 1, window.state.files(identity))
            receipt["steps"].append("actual-process-reopen-all-exact-bundles")
            finish()
        else:
            assert window.state.history() == []
            window.run_button.invoke()
            assert (
                window.state.history() == []
                and "permission" in window.status.get().lower()
            )
            start(0)

    checked(begin)
