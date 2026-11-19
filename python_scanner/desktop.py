"""Optional Kivy desktop interface for the shared scanner engine."""

from __future__ import annotations

import threading
from pathlib import Path

try:
    from kivy.app import App
    from kivy.clock import Clock
    from kivy.uix.boxlayout import BoxLayout
    from kivy.uix.button import Button
    from kivy.uix.label import Label
    from kivy.uix.textinput import TextInput
except ImportError as exc:
    raise SystemExit(
        "The desktop interface requires Kivy. Install it with: "
        'python -m pip install -e ".[desktop]"'
    ) from exc

from python_scanner.core.engine import Scanner
from python_scanner.reporting import to_text


class ScannerDesktopApp(App):
    title = "Python Scanner"

    def build(self):
        root = BoxLayout(orientation="vertical", padding=12, spacing=10)
        self.path_input = TextInput(
            text=str(Path.cwd()), hint_text="Path to a Python file or project folder",
            size_hint_y=None, height=48, multiline=False,
        )
        self.status = Label(
            text="Ready — scans run locally and do not execute project code.",
            size_hint_y=None, height=36,
        )
        self.output = TextInput(text="", readonly=True, font_size=13)
        scan_button = Button(text="Analyze project", size_hint_y=None, height=48)
        scan_button.bind(on_release=self.start_scan)
        root.add_widget(self.path_input)
        root.add_widget(scan_button)
        root.add_widget(self.status)
        root.add_widget(self.output)
        return root

    def start_scan(self, *_):
        target = self.path_input.text.strip()
        self.status.text = "Scanning…"
        self.output.text = ""
        threading.Thread(target=self._scan_worker, args=(target,), daemon=True).start()

    def _scan_worker(self, target: str):
        try:
            result = Scanner().scan(target)
            text = to_text(result)
            status = f"Finished — score {result.score}/100 · {result.scanned_files} files"
        except Exception as exc:
            text = str(exc)
            status = "Scan failed"
        Clock.schedule_once(lambda _dt: self._show_result(status, text), 0)

    def _show_result(self, status: str, text: str):
        self.status.text = status
        self.output.text = text


if __name__ == "__main__":
    ScannerDesktopApp().run()
