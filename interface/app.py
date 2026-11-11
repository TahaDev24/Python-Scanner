"""Kivy mobile interface for Python Scanner.

The scanning engine lives in :mod:`core.engine`. This module owns only the
presentation layer and Kivy application lifecycle.
"""

from __future__ import annotations

from core.engine import *
from core.engine import _write_startup_log

# Import Kivy defensively: keep a readable startup diagnostic if unavailable.
KIVY_AVAILABLE = False
KIVY_IMPORT_ERROR = ""
try:
    from kivy.app import App
    from kivy.clock import Clock
    from kivy.core.window import Window
    from kivy.graphics import Color, RoundedRectangle, Line, Ellipse, Rectangle
    from kivy.metrics import dp, sp
    from kivy.uix.boxlayout import BoxLayout
    from kivy.uix.button import Button
    from kivy.uix.checkbox import CheckBox
    from kivy.uix.filechooser import FileChooserListView
    from kivy.uix.gridlayout import GridLayout
    from kivy.uix.label import Label
    from kivy.uix.popup import Popup
    from kivy.uix.progressbar import ProgressBar
    from kivy.uix.screenmanager import Screen, ScreenManager, FadeTransition
    from kivy.uix.scrollview import ScrollView
    from kivy.uix.spinner import Spinner
    from kivy.uix.textinput import TextInput
    from kivy.uix.widget import Widget
    KIVY_AVAILABLE = True
except Exception as _kivy_error:
    KIVY_IMPORT_ERROR = f"{type(_kivy_error).__name__}: {_kivy_error}"
    _write_startup_log("KIVY_IMPORT_FAILED\n" + traceback.format_exc())

# UI implementation retained from the original application.
# Palette: deep ink background with turquoise/cyan neon accents.
C_BG = (0.018, 0.035, 0.055, 1)
C_SURFACE = (0.035, 0.075, 0.095, 1)
C_SURFACE_2 = (0.050, 0.105, 0.130, 1)
C_SURFACE_3 = (0.065, 0.135, 0.160, 1)
C_BORDER = (0.10, 0.32, 0.34, 1)
C_TEXT = (0.91, 0.98, 0.98, 1)
C_MUTED = (0.48, 0.66, 0.68, 1)
C_ACCENT = (0.12, 0.94, 0.84, 1)
C_ACCENT_SOFT = (0.10, 0.55, 0.52, 1)
C_BLUE = (0.30, 0.67, 1.0, 1)
C_RED = (1.0, 0.31, 0.40, 1)
C_ORANGE = (1.0, 0.68, 0.25, 1)
C_GREEN = (0.24, 0.90, 0.62, 1)


if KIVY_AVAILABLE:
    class NeonProgress(Widget):
        """Small custom progress indicator; avoids version-specific ProgressBar properties."""
        def __init__(self, **kwargs):
            self.max = 1.0
            self.value = 0.0
            super().__init__(**kwargs)
            with self.canvas:
                Color(*C_SURFACE_3)
                self._track = RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(5)])
                Color(*C_ACCENT)
                self._fill = RoundedRectangle(pos=self.pos, size=(0, self.height), radius=[dp(5)])
            self.bind(pos=self._update_bar, size=self._update_bar)
            self._update_bar()

        def _update_bar(self, *_):
            maximum = max(1.0, float(self.max))
            ratio = max(0.0, min(1.0, float(self.value) / maximum))
            self._track.pos = self.pos
            self._track.size = self.size
            self._fill.pos = self.pos
            self._fill.size = (self.width * ratio, self.height)


    class NeonSurface(BoxLayout):
        """Reusable rounded panel with a subtle turquoise rim."""
        def __init__(self, fill=C_SURFACE, radius=dp(18), **kwargs):
            super().__init__(**kwargs)
            self._fill = fill
            self._radius = radius
            with self.canvas.before:
                self._bg_color = Color(*fill)
                self._bg = RoundedRectangle(pos=self.pos, size=self.size,
                                            radius=[radius])
                self._border_color = Color(*C_BORDER)
                self._border = Line(rounded_rectangle=(self.x, self.y,
                                                       self.width, self.height, radius),
                                    width=0.85)
            self.bind(pos=self._sync_canvas, size=self._sync_canvas)

        def _sync_canvas(self, *_):
            self._bg.pos = self.pos
            self._bg.size = self.size
            self._border.rounded_rectangle = (self.x, self.y, self.width,
                                              self.height, self._radius)


    class NeonButton(Button):
        def __init__(self, fill=C_ACCENT, text_color=C_BG, outline=False, **kwargs):
            self.fill = fill
            self.text_color = text_color
            self.outline = outline
            kwargs.setdefault("background_normal", "")
            kwargs.setdefault("background_down", "")
            kwargs.setdefault("background_color", (0, 0, 0, 0))
            kwargs.setdefault("color", text_color)
            kwargs.setdefault("bold", True)
            kwargs.setdefault("font_size", sp(14))
            kwargs.setdefault("size_hint_y", None)
            kwargs.setdefault("height", dp(50))
            super().__init__(**kwargs)
            with self.canvas.before:
                self._btn_color = Color(*(C_SURFACE_2 if outline else fill))
                self._btn_rect = RoundedRectangle(pos=self.pos, size=self.size,
                                                   radius=[dp(14)])
                self._line_color = Color(*(C_ACCENT if outline else fill))
                self._btn_line = Line(rounded_rectangle=(self.x, self.y,
                                                          self.width, self.height,
                                                          dp(14)), width=0.9 if outline else 0)
            self.bind(pos=self._sync_canvas, size=self._sync_canvas,
                      state=self._sync_state, disabled=self._sync_state)
            self._sync_state()

        def _sync_canvas(self, *_):
            self._btn_rect.pos = self.pos
            self._btn_rect.size = self.size
            self._btn_line.rounded_rectangle = (self.x, self.y, self.width,
                                                self.height, dp(14))

        def _sync_state(self, *_):
            if self.disabled:
                self._btn_color.rgba = (0.08, 0.12, 0.14, 1)
                self.color = C_MUTED
            elif self.state == "down":
                self._btn_color.rgba = tuple(v * 0.78 for v in self.fill[:3]) + (1,)
                self.color = self.text_color
            else:
                self._btn_color.rgba = C_SURFACE_2 if self.outline else self.fill
                self.color = C_TEXT if self.outline else self.text_color


    class NeonLabel(Label):
        def __init__(self, text="", color=C_TEXT, size=13, height=30,
                     halign="left", valign="middle", **kwargs):
            kwargs.setdefault("size_hint_y", None)
            kwargs.setdefault("height", dp(height))
            kwargs.setdefault("font_size", sp(size))
            kwargs.setdefault("color", color)
            kwargs.setdefault("halign", halign)
            kwargs.setdefault("valign", valign)
            super().__init__(text=text, **kwargs)
            self.bind(size=self._sync_text)
            self._sync_text()

        def _sync_text(self, *_):
            self.text_size = (max(1, self.width), None)


    class NeonMetric(NeonSurface):
        def __init__(self, caption, value="—", accent=C_ACCENT, **kwargs):
            super().__init__(orientation="vertical", padding=dp(12), spacing=dp(2),
                             size_hint_y=None, height=dp(98), **kwargs)
            self.add_widget(NeonLabel(text=value, size=24, color=accent,
                                      height=dp(42), bold=True, halign="center"))
            self.value_label = self.children[0]
            self.add_widget(NeonLabel(text=caption, size=10, color=C_MUTED,
                                      height=dp(24), bold=True, halign="center"))


    class PythonScannerApp(App):
        title = APP_TITLE

        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.engine = build_default_engine()
            self.events = queue.Queue()
            self.task = None
            self.target = None
            self.last_result = None
            self.findings = []
            self.active_filter = "All"
            self.search_query = ""
            self.busy = False
            self.visible_limit = 120
            self._finding_popup = None
            self._toast_popup = None
            self._scan_config = None
            self._picker_request_code = 7412
            self._picker_mode = None
            self._android_picker_bound = False
            self._picker_activity = None
            self._last_picker_error = ""

        # ----- Startup / shell -----------------------------------------
        def build(self):
            try:
                Window.clearcolor = C_BG
                try:
                    Window.softinput_mode = "below_target"
                except Exception:
                    pass
                self.screen_manager = ScreenManager(transition=FadeTransition(duration=0.12))
                for screen_name, factory in (
                    ("home", self._build_home),
                    ("scan", self._build_scan),
                    ("results", self._build_results),
                    ("settings", self._build_settings),
                ):
                    screen = Screen(name=screen_name)
                    screen.add_widget(factory())
                    self.screen_manager.add_widget(screen)
                self.bottom_nav = self._build_bottom_nav()
                root = BoxLayout(orientation="vertical", spacing=0)
                root.add_widget(self.screen_manager)
                root.add_widget(self.bottom_nav)
                Clock.schedule_interval(self._poll_events, 0.10)
                return root
            except Exception:
                detail = traceback.format_exc()
                _write_startup_log("UI_BUILD_FAILED\n" + detail)
                return self._emergency_view(detail)

        def _emergency_view(self, detail):
            root = BoxLayout(orientation="vertical", padding=dp(22), spacing=dp(14))
            with root.canvas.before:
                Color(*C_BG)
                root._fallback_bg = Rectangle(pos=root.pos, size=root.size)
            root.bind(pos=lambda w, *_: setattr(w._fallback_bg, "pos", w.pos),
                      size=lambda w, *_: setattr(w._fallback_bg, "size", w.size))
            root.add_widget(NeonLabel(text="PYTHON SCANNER", size=22, color=C_ACCENT,
                                      bold=True, height=dp(48)))
            root.add_widget(NeonLabel(text="The main interface could not be built. This diagnostic screen is available instead.",
                                      size=15, color=C_TEXT, height=dp(60)))
            root.add_widget(NeonLabel(text="Error details were saved to python_scanner.log.",
                                      size=12, color=C_MUTED, height=dp(45)))
            error_box = ScrollView(do_scroll_x=False)
            error_label = Label(text=detail[-5000:], color=C_MUTED, font_size=sp(10),
                                halign="left", valign="top", size_hint_y=None)
            error_label.bind(width=lambda w, width: setattr(w, "text_size", (width, None)),
                             texture_size=lambda w, size: setattr(w, "height", size[1]))
            error_box.add_widget(error_label)
            root.add_widget(error_box)
            return root

        def _page(self, heading, subtitle):
            page = BoxLayout(orientation="vertical", padding=(dp(16), dp(12), dp(16), dp(8)),
                             spacing=dp(10))
            top = BoxLayout(size_hint_y=None, height=dp(66), spacing=dp(10))
            logo = NeonSurface(size_hint=(None, None), size=(dp(52), dp(52)),
                               padding=dp(2), radius=dp(16), fill=C_SURFACE_3)
            logo.add_widget(NeonLabel(text="</>", size=19, color=C_ACCENT,
                                      bold=True, halign="center"))
            top.add_widget(logo)
            titles = BoxLayout(orientation="vertical", spacing=0)
            titles.add_widget(NeonLabel(text=heading, size=20, height=dp(34), bold=True))
            titles.add_widget(NeonLabel(text=subtitle, size=10, height=dp(23), color=C_MUTED))
            top.add_widget(titles)
            page.add_widget(top)
            return page

        def _scroll(self, spacing=dp(11)):
            scroll = ScrollView(do_scroll_x=False, bar_width=dp(3),
                                scroll_type=["bars", "content"])
            body = BoxLayout(orientation="vertical", size_hint_y=None, spacing=spacing,
                             padding=(0, 0, 0, dp(12)))
            body.bind(minimum_height=body.setter("height"))
            scroll.add_widget(body)
            return scroll, body

        def _card(self, heading=None, hint=None, height=None, fill=C_SURFACE):
            card = NeonSurface(orientation="vertical", padding=dp(14), spacing=dp(8),
                               size_hint_y=None, height=height if height is not None else dp(80),
                               fill=fill)
            if height is None:
                card.bind(minimum_height=card.setter("height"))
            if heading:
                card.add_widget(NeonLabel(text=heading, size=14, color=C_TEXT,
                                          bold=True, height=dp(28)))
            if hint:
                card.add_widget(NeonLabel(text=hint, size=10, color=C_MUTED,
                                          height=dp(26)))
            return card

        def _button(self, text, callback, secondary=False, height=48):
            button = NeonButton(text=text,
                                fill=C_SURFACE_2 if secondary else C_ACCENT,
                                text_color=C_TEXT if secondary else C_BG,
                                outline=secondary, height=dp(height))
            button.bind(on_release=lambda *_: callback())
            return button

        def _build_bottom_nav(self):
            nav = NeonSurface(orientation="horizontal", padding=(dp(7), dp(5)),
                              spacing=dp(2), size_hint_y=None, height=dp(62),
                              radius=dp(14), fill=C_SURFACE)
            for title, page in (("Home", "home"), ("Scan", "scan"),
                                ("Results", "results"), ("Settings", "settings")):
                button = Button(text=title, background_normal="",
                                background_color=(0, 0, 0, 0),
                                color=C_ACCENT if self.screen_manager.current == page else C_MUTED,
                                font_size=sp(11), bold=True)
                button.bind(on_release=lambda _b, dest=page: self.go(dest))
                nav.add_widget(button)
            return nav

        def go(self, page):
            self.screen_manager.current = page
            self._refresh_nav()

        def _refresh_nav(self):
            if not hasattr(self, "bottom_nav"):
                return
            self.bottom_nav.clear_widgets()
            for title, page in (("Home", "home"), ("Scan", "scan"),
                                ("Results", "results"), ("Settings", "settings")):
                button = Button(text=title, background_normal="",
                                background_color=(0, 0, 0, 0),
                                color=C_ACCENT if self.screen_manager.current == page else C_MUTED,
                                font_size=sp(11), bold=True)
                button.bind(on_release=lambda _b, dest=page: self.go(dest))
                self.bottom_nav.add_widget(button)

        # ----- Home ----------------------------------------------------
        def _build_home(self):
            page = self._page("Python Scanner", "Professional Python static analysis")
            scroll, body = self._scroll()
            hero = NeonSurface(orientation="vertical", padding=dp(18), spacing=dp(10),
                               size_hint_y=None, height=dp(220), fill=C_SURFACE_2)
            hero.add_widget(NeonLabel(text="Inspect your code with confidence.", size=22,
                                      bold=True, color=C_TEXT, height=dp(42)))
            hero.add_widget(NeonLabel(
                text="Detect syntax errors, suspicious patterns, security risks, exposed secrets, and dependency issues without executing your code.",
                size=11, color=C_MUTED, height=dp(62)))
            hero.add_widget(self._button("＋   START NEW SCAN", lambda: self.go("scan")))
            body.add_widget(hero)

            stats = GridLayout(cols=2, spacing=dp(9), size_hint_y=None, height=dp(100))
            self.home_files = NeonMetric("Files Scanned", "—")
            self.home_findings = NeonMetric("Findings", "—", accent=C_BLUE)
            stats.add_widget(self.home_files)
            stats.add_widget(self.home_findings)
            body.add_widget(stats)

            recent = self._card("Latest Scan", height=dp(142))
            self.home_latest = NeonLabel(text="No scans have been run yet.", size=11,
                                         color=C_MUTED, height=dp(48))
            recent.add_widget(self.home_latest)
            recent.add_widget(self._button("VIEW RESULTS", lambda: self.go("results"),
                                           secondary=True, height=42))
            body.add_widget(recent)

            capabilities = self._card("WHAT WE CHECK", height=dp(208))
            for line in (
                "✓  Python syntax and AST structure",
                "✓  Common bugs and function complexity",
                "✓  Risky code patterns and security settings",
                "✓  Potential secrets with values masked",
                "✓  Dependencies and optional Ruff / Bandit tools",
            ):
                capabilities.add_widget(NeonLabel(text=line, size=10, color=C_MUTED,
                                                  height=dp(25)))
            body.add_widget(capabilities)
            page.add_widget(scroll)
            return page

        # ----- Scan page -----------------------------------------------
        def _build_scan(self):
            page = self._page("New Scan", "Choose a Python file or project folder")
            scroll, body = self._scroll()
            target_card = self._card("1. SELECT TARGET", "Choose a file from device storage or scan a project folder")
            self.target_label = NeonLabel(text="No target selected", size=11,
                                          color=C_MUTED, height=dp(52))
            target_card.add_widget(self.target_label)
            picker_row = GridLayout(cols=2, spacing=dp(8), size_hint_y=None,
                                    height=dp(52))
            picker_row.add_widget(self._button("CHOOSE .PY FILE", self.choose_file,
                                               secondary=True))
            picker_row.add_widget(self._button("CHOOSE FOLDER", self.choose_folder,
                                               secondary=True))
            target_card.add_widget(picker_row)
            body.add_widget(target_card)

            options = self._card("2. SCAN OPTIONS")
            recursive_row = BoxLayout(size_hint_y=None, height=dp(42), spacing=dp(8))
            recursive_row.add_widget(NeonLabel(text="Include subfolders", size=12,
                                               color=C_TEXT, height=dp(40)))
            self.recursive_check = CheckBox(active=True, size_hint=(None, None),
                                            size=(dp(46), dp(42)))
            recursive_row.add_widget(self.recursive_check)
            options.add_widget(recursive_row)
            options.add_widget(NeonLabel(text="Maximum file size (MB)", size=10,
                                         color=C_MUTED, height=dp(24)))
            self.max_size_input = TextInput(text=str(DEFAULT_MAX_FILE_MB), multiline=False,
                                            input_filter="float", size_hint_y=None,
                                            height=dp(44), padding=(dp(12), dp(10)),
                                            background_normal="", background_active="",
                                            background_color=C_SURFACE_2,
                                            foreground_color=C_TEXT, cursor_color=C_ACCENT,
                                            hint_text_color=C_MUTED, font_size=sp(14))
            options.add_widget(self.max_size_input)
            options.add_widget(NeonLabel(text="Ignored folders", size=10,
                                         color=C_MUTED, height=dp(24)))
            self.ignored_input = TextInput(
                text=", ".join(DEFAULT_IGNORED_DIRS[:12]), multiline=False,
                size_hint_y=None, height=dp(44), padding=(dp(12), dp(10)),
                background_normal="", background_active="",
                background_color=C_SURFACE_2, foreground_color=C_TEXT,
                cursor_color=C_ACCENT, font_size=sp(11))
            options.add_widget(self.ignored_input)
            body.add_widget(options)

            status = self._card("3. SCAN STATUS")
            self.scan_status = NeonLabel(text="Ready to scan", size=11,
                                         color=C_MUTED, height=dp(42))
            status.add_widget(self.scan_status)
            self.progress = NeonProgress(size_hint_y=None, height=dp(9))
            status.add_widget(self.progress)
            controls = GridLayout(cols=2, spacing=dp(8), size_hint_y=None,
                                  height=dp(50))
            self.scan_button = self._button("START SCAN", self.start_scan)
            self.cancel_button = self._button("CANCEL SCAN", self.cancel_scan,
                                               secondary=True)
            self.cancel_button.disabled = True
            controls.add_widget(self.scan_button)
            controls.add_widget(self.cancel_button)
            status.add_widget(controls)
            status.add_widget(NeonLabel(
                text="Safety: selected source files are read and analyzed, never executed.",
                size=9, color=C_MUTED, height=dp(42)))
            body.add_widget(status)
            page.add_widget(scroll)
            return page

        # ----- Results page --------------------------------------------
        def _build_results(self):
            page = self._page("Scan Report", "Tap any finding to inspect details")
            scroll, body = self._scroll(spacing=dp(9))
            summary = self._card("SCAN SUMMARY")
            self.results_summary = NeonLabel(text="No report available yet.", size=10,
                                             color=C_MUTED, height=dp(52))
            summary.add_widget(self.results_summary)
            metrics = GridLayout(cols=3, spacing=dp(6), size_hint_y=None, height=dp(102))
            self.result_errors = NeonMetric("Error", "—", accent=C_RED)
            self.result_warnings = NeonMetric("Warning", "—", accent=C_ORANGE)
            self.result_info = NeonMetric("Info", "—", accent=C_BLUE)
            for metric in (self.result_errors, self.result_warnings, self.result_info):
                metrics.add_widget(metric)
            summary.add_widget(metrics)
            body.add_widget(summary)

            controls = self._card("FILTER FINDINGS")
            self.filter_spinner = Spinner(text="All", values=("All", "Error", "Warning", "Info"),
                                          size_hint_y=None, height=dp(44),
                                          background_normal="", background_color=C_SURFACE_2,
                                          color=C_TEXT, font_size=sp(12))
            self.filter_spinner.bind(text=self._on_filter)
            controls.add_widget(self.filter_spinner)
            self.search_input = TextInput(hint_text="Search message, file, or rule ID...",
                                          multiline=False, size_hint_y=None, height=dp(44),
                                          padding=(dp(12), dp(10)), background_normal="",
                                          background_active="", background_color=C_SURFACE_2,
                                          foreground_color=C_TEXT, hint_text_color=C_MUTED,
                                          cursor_color=C_ACCENT, font_size=sp(11))
            self.search_input.bind(text=self._on_search)
            controls.add_widget(self.search_input)
            self.findings_count = NeonLabel(text="0 findings", color=C_ACCENT, size=10,
                                            height=dp(25), bold=True)
            controls.add_widget(self.findings_count)
            body.add_widget(controls)

            self.findings_list = BoxLayout(orientation="vertical", size_hint_y=None,
                                           spacing=dp(8))
            self.findings_list.bind(minimum_height=self.findings_list.setter("height"))
            body.add_widget(self.findings_list)
            self.load_more_button = self._button("LOAD MORE", self._load_more,
                                                  secondary=True)
            self.load_more_button.disabled = True
            body.add_widget(self.load_more_button)
            tools = self._card("TOOL STATUS")
            self.tool_status_label = NeonLabel(text="Tool status will appear here after a scan.",
                                               size=10, color=C_MUTED, height=dp(66))
            tools.add_widget(self.tool_status_label)
            body.add_widget(tools)
            footer = GridLayout(cols=2, spacing=dp(8), size_hint_y=None, height=dp(48))
            self.export_button = self._button("EXPORT JSON REPORT", self.export_report,
                                              secondary=True)
            self.export_button.disabled = True
            footer.add_widget(self.export_button)
            footer.add_widget(self._button("SCAN AGAIN", lambda: self.go("scan")))
            body.add_widget(footer)
            page.add_widget(scroll)
            return page

        def _build_settings(self):
            page = self._page("Settings", "Engine information, privacy, and limitations")
            scroll, body = self._scroll()
            about = self._card("ABOUT")
            about.add_widget(NeonLabel(text=f"Version {APP_VERSION}  •  Mobile Edition",
                                       size=11, color=C_ACCENT, height=dp(28)))
            about.add_widget(NeonLabel(
                text="Python Scanner performs static analysis. It never runs or imports selected project files; it only reads their source and structure.",
                size=11, color=C_MUTED, height=dp(68)))
            body.add_widget(about)
            engines = self._card("ANALYSIS ENGINES")
            for label in (
                "AST and syntax checks: Python built-in parser",
                "Bug and security checks: built-in AST rules",
                "Secrets: pattern and entropy checks with value masking",
                "Dependencies: imports compared with project manifests",
                "Ruff and Bandit: optional tools, enabled when installed",
            ):
                engines.add_widget(NeonLabel(text="•  " + label, size=10,
                                             color=C_MUTED, height=dp(30)))
            body.add_widget(engines)
            privacy = self._card("PRIVACY")
            privacy.add_widget(NeonLabel(
                text="Project contents are not uploaded. Reports are created only when you export them. Detected secret values are masked in reports.",
                size=11, color=C_MUTED, height=dp(78)))
            body.add_widget(privacy)
            limitations = self._card("STATIC ANALYSIS LIMITATIONS")
            limitations.add_widget(NeonLabel(
                text="Static analysis cannot prove every data-dependent, external-service, or runtime issue. Potential findings include a confidence level. Install Ruff and Bandit in a supported environment for additional checks.",
                size=11, color=C_MUTED, height=dp(100)))
            body.add_widget(limitations)
            page.add_widget(scroll)
            return page

        # ----- File and folder picker ----------------------------------
        def _picker_start(self):
            candidates = []
            if self.target:
                candidates.append(self.target if self.target.is_dir() else self.target.parent)
            candidates.extend((Path("/storage/emulated/0"), Path.home(), Path.cwd()))
            for candidate in candidates:
                try:
                    if candidate.exists() and candidate.is_dir() and os.access(str(candidate), os.R_OK):
                        return str(candidate)
                except OSError:
                    continue
            return str(Path.home())

        def _android_open_picker(self, folder=False):
            """Legacy SAF path retained for reference; not used by _show_picker."""
            try:
                self._picker_mode = "folder" if folder else "file"
                # Pydroid callbacks can originate outside Android's UI thread.
                # Clock.schedule_once guarantees the Java activity call is made
                # from Kivy's main thread instead of the worker thread.
                Clock.schedule_once(
                    lambda _dt: self._launch_android_picker_on_ui(folder), 0
                )
                return True
            except Exception:
                detail = traceback.format_exc()
                self._last_picker_error = detail.splitlines()[-1] if detail.splitlines() else "Unknown Android picker error"
                _write_startup_log("ANDROID_SAF_SCHEDULE_FAILED\n" + detail)
                return False

        def _launch_android_picker_on_ui(self, folder=False):
            """Launch Android's document picker from Pydroid's main activity."""
            try:
                # Pydroid uses the Ren'Py activity bootstrap. Set the Java
                # thread context loader to that activity's loader before
                # registering python-for-android's Java listener proxy.
                from android import activity as android_activity
                from jnius import autoclass, cast

                PythonActivity = autoclass("org.renpy.android.PythonActivity")
                raw_activity = PythonActivity.mActivity
                if raw_activity is None:
                    raise RuntimeError("Pydroid did not expose its current Android activity")

                Thread = autoclass("java.lang.Thread")
                java_thread = Thread.currentThread()
                previous_loader = java_thread.getContextClassLoader()
                activity_loader = raw_activity.getClass().getClassLoader()
                java_thread.setContextClassLoader(activity_loader)

                try:
                    if not self._android_picker_bound:
                        android_activity.bind(
                            on_activity_result=self._on_android_activity_result
                        )
                        self._android_picker_bound = True
                finally:
                    # Keep the app's Java thread context unchanged after
                    # proxy creation; Pyjnius retains the listener reference.
                    java_thread.setContextClassLoader(previous_loader)

                activity_instance = cast("android.app.Activity", raw_activity)
                self._picker_activity = activity_instance
                Intent = autoclass("android.content.Intent")

                if folder:
                    intent = Intent("android.intent.action.OPEN_DOCUMENT_TREE")
                    flags = (Intent.FLAG_GRANT_READ_URI_PERMISSION |
                             Intent.FLAG_GRANT_WRITE_URI_PERMISSION |
                             Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
                else:
                    intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
                    intent.addCategory(Intent.CATEGORY_OPENABLE)
                    intent.setType("*/*")
                    flags = (Intent.FLAG_GRANT_READ_URI_PERMISSION |
                             Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)

                intent.addFlags(flags)
                self._picker_mode = "folder" if folder else "file"
                activity_instance.startActivityForResult(
                    intent, int(self._picker_request_code)
                )
            except Exception as exc:
                detail = traceback.format_exc()
                # JavaException text contains the useful exception class and
                # message; the final traceback line often contains only
                # Thread.run(), which is not the actual cause.
                message = str(exc).strip() or type(exc).__name__
                self._last_picker_error = message[:240]
                _write_startup_log(
                    "ANDROID_PICKER_LAUNCH_FAILED\nEXCEPTION: " + message +
                    "\nTRACEBACK:\n" + detail
                )
                self._picker_mode = None
                self._toast("Picker failed: " + self._last_picker_error[:120])

        def _on_android_activity_result(self, request_code, result_code, intent):
            if request_code != self._picker_request_code:
                return
            mode = self._picker_mode
            self._picker_mode = None
            if result_code != -1 or intent is None:
                return
            try:
                from jnius import autoclass
                activity = getattr(self, "_picker_activity", None)
                if activity is None:
                    raise RuntimeError("The Android activity reference was lost before selection returned")
                DocumentsContract = autoclass("android.provider.DocumentsContract")
                OpenableColumns = autoclass("android.provider.OpenableColumns")
                resolver = activity.getContentResolver()
                uri = intent.getData()
                if uri is None:
                    raise RuntimeError("Android returned an empty document URI")
                try:
                    activity.getContentResolver().takePersistableUriPermission(
                        uri, intent.getFlags() & 3)
                except Exception:
                    pass

                stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                import_root = Path(self.user_data_dir) / "scanner_imports" / stamp
                import_root.mkdir(parents=True, exist_ok=True)
                if mode == "file":
                    name = self._android_display_name(resolver, uri, OpenableColumns)
                    if not name.lower().endswith(".py"):
                        self._toast("Select a Python .py file.")
                        return
                    destination = import_root / Path(name).name
                    self._copy_android_uri(resolver, uri, destination)
                    self.set_target(destination)
                elif mode == "folder":
                    copied = self._copy_android_tree(resolver, DocumentsContract, uri, import_root)
                    if copied < 1:
                        self._toast("No readable Python files were found in this folder.")
                        return
                    self.set_target(import_root)
                    self._toast(f"Folder imported: {copied} files ready to scan.")
            except Exception as exc:
                detail = traceback.format_exc()
                message = str(exc).strip() or type(exc).__name__
                _write_startup_log(
                    "ANDROID_DOCUMENT_IMPORT_FAILED\nEXCEPTION: " + message +
                    "\nTRACEBACK:\n" + detail
                )
                self._toast("Import failed: " + message[:120])

        @staticmethod
        def _android_display_name(resolver, uri, OpenableColumns):
            cursor = resolver.query(uri, [OpenableColumns.DISPLAY_NAME], None, None, None)
            if cursor is not None:
                try:
                    if cursor.moveToFirst():
                        return str(cursor.getString(0) or "selected_file.py")
                finally:
                    cursor.close()
            return "selected_file.py"

        @staticmethod
        def _copy_android_uri(resolver, uri, destination):
            """Copy a SAF document through its file descriptor, not a guessed path."""
            descriptor = resolver.openFileDescriptor(uri, "r")
            if descriptor is None:
                raise OSError("Android could not open the selected document")
            fd = os.dup(descriptor.getFd())
            descriptor.close()
            with os.fdopen(fd, "rb") as source, open(destination, "wb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)

        def _copy_android_tree(self, resolver, DocumentsContract, tree_uri, destination):
            """Import a selected folder from SAF into app storage for normal Path-based scanning."""
            from jnius import autoclass
            Document = autoclass("android.provider.DocumentsContract$Document")
            root_id = DocumentsContract.getTreeDocumentId(tree_uri)
            count = [0]
            total_bytes = [0]
            max_files = 10000
            max_total = 512 * 1024 * 1024

            def walk(parent_id, local_dir, depth=0):
                if depth > 40 or count[0] >= max_files:
                    return
                children_uri = DocumentsContract.buildChildDocumentsUriUsingTree(tree_uri, parent_id)
                columns = [Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME,
                           Document.COLUMN_MIME_TYPE, Document.COLUMN_SIZE]
                cursor = resolver.query(children_uri, columns, None, None, None)
                if cursor is None:
                    return
                try:
                    while cursor.moveToNext() and count[0] < max_files:
                        doc_id = str(cursor.getString(0))
                        name = str(cursor.getString(1) or "item")
                        mime = str(cursor.getString(2) or "")
                        safe_name = Path(name).name or "item"
                        if safe_name in (".", ".."):
                            continue
                        if mime == Document.MIME_TYPE_DIR:
                            child_dir = local_dir / safe_name
                            child_dir.mkdir(parents=True, exist_ok=True)
                            walk(doc_id, child_dir, depth + 1)
                        elif safe_name.lower().endswith(".py") or safe_name.lower() in (
                                "requirements.txt", "pyproject.toml"):
                            size = cursor.getLong(3) if not cursor.isNull(3) else 0
                            if size > MAX_FILE_MB_LIMIT * 1024 * 1024:
                                continue
                            if total_bytes[0] + max(0, size) > max_total:
                                return
                            document_uri = DocumentsContract.buildDocumentUriUsingTree(tree_uri, doc_id)
                            target = local_dir / safe_name
                            self._copy_android_uri(resolver, document_uri, target)
                            actual = target.stat().st_size
                            total_bytes[0] += actual
                            count[0] += 1
                finally:
                    cursor.close()

            walk(root_id, destination)
            return count[0]

        def _request_android_storage_access(self):
            """Ask Pydroid for Android's broad file access without SAF callbacks.

            Pydroid's android.activity result bridge can fail on its alternate
            PythonActivity class loader. This route deliberately avoids that
            bridge: Android opens the permission settings as a normal Activity,
            and Kivy's own file browser reads storage after the user returns.
            """
            try:
                from jnius import autoclass, cast
                BuildVersion = autoclass("android.os.Build$VERSION")
                if int(BuildVersion.SDK_INT) < 30:
                    return True
                Environment = autoclass("android.os.Environment")
                if bool(Environment.isExternalStorageManager()):
                    return True
                PythonActivity = None
                activity = None
                for class_name in ("org.renpy.android.PythonActivity",
                                   "org.kivy.android.PythonActivity"):
                    try:
                        PythonActivity = autoclass(class_name)
                        raw = PythonActivity.mActivity
                        if raw is not None:
                            activity = cast("android.app.Activity", raw)
                            break
                    except Exception:
                        continue
                if activity is None:
                    raise RuntimeError("Pydroid Android activity is unavailable")
                Intent = autoclass("android.content.Intent")
                Uri = autoclass("android.net.Uri")
                Settings = autoclass("android.provider.Settings")
                intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                intent.setData(Uri.parse("package:" + str(activity.getPackageName())))
                try:
                    activity.startActivity(intent)
                except Exception:
                    # Some Android builds expose only the general access page.
                    fallback = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                    activity.startActivity(fallback)
                self._toast("Allow Pydroid to access all files. Return here and tap Select again.")
                return False
            except Exception:
                _write_startup_log("ANDROID_STORAGE_PERMISSION_FAILED\n" + traceback.format_exc())
                # Do not block the in-app browser if the device already grants
                # ordinary storage access or uses an older Android release.
                return True

        def _show_picker(self, folder=False):
            android_runtime = (sys.platform == "android" or
                               "ANDROID_ARGUMENT" in os.environ or
                               "ANDROID_ROOT" in os.environ or
                               os.path.isdir("/system/bin"))
            # On Android, always use the system DocumentsUI picker. The Kivy
            # FileChooserListView only sees app-accessible paths and often
            # appears empty on modern Android scoped-storage devices.
            if android_runtime:
                self._android_open_picker(folder=folder)
                return

            # Desktop fallback only.
            try:
                chooser = FileChooserListView(
                    path=self._picker_start(), dirselect=folder,
                    filters=[] if folder else ["*.py"], multiselect=False,
                    show_hidden=False)
                body = BoxLayout(orientation="vertical", spacing=dp(8), padding=dp(10))
                body.add_widget(chooser)
                popup = Popup(title="Choose Project Folder" if folder else "Choose Python File",
                              content=body, size_hint=(0.97, 0.92),
                              separator_color=C_ACCENT)
                actions = GridLayout(cols=2, spacing=dp(8), size_hint_y=None,
                                     height=dp(48))
                actions.add_widget(self._button("CANCEL", popup.dismiss,
                                                 secondary=True, height=46))

                def accept(*_):
                    selected = chooser.selection[0] if chooser.selection else (
                        chooser.path if folder else "")
                    if not selected:
                        self._toast("Choose a file or folder first.")
                        return
                    selected_path = Path(selected).expanduser()
                    if folder and not selected_path.is_dir():
                        self._toast("Please choose a folder for this option.")
                        return
                    if not folder and (not selected_path.is_file() or selected_path.suffix.lower() != ".py"):
                        self._toast("Only .py files are supported.")
                        return
                    popup.dismiss()
                    self.set_target(selected_path)

                actions.add_widget(self._button("SELECT THIS", accept, height=46))
                body.add_widget(actions)
                popup.open()
            except Exception:
                _write_startup_log("FILE_PICKER_FAILED\n" + traceback.format_exc())
                self._toast("The built-in file browser could not open.")

        def choose_file(self):
            self._show_picker(folder=False)

        def choose_folder(self):
            self._show_picker(folder=True)

        def set_target(self, target):
            path = Path(target).expanduser()
            if not path.exists() or not (path.is_file() or path.is_dir()):
                self._toast("The selected path is not readable.")
                return
            if path.is_file() and path.suffix.lower() != ".py":
                self._toast("Please select a .py file.")
                return
            self.target = path
            self.last_result = None
            self.findings = []
            self.visible_limit = 120
            self.export_button.disabled = True
            self._clear_results()
            kind = "Project folder" if path.is_dir() else "Python file"
            self.target_label.text = f"{kind}:  {path.name}\n{path.parent if path.is_file() else path}"
            self.target_label.color = C_TEXT
            self.scan_status.text = "Target selected. Ready to scan."
            self.scan_status.color = C_GREEN
            self.scan_button.disabled = self.busy
            self.go("scan")

        # ----- Scan lifecycle ------------------------------------------
        def _make_config(self):
            if not self.target:
                self._toast("Choose a file or folder first.")
                return None
            try:
                size_mb = float(self.max_size_input.text.strip())
                if not 0.05 <= size_mb <= MAX_FILE_MB_LIMIT:
                    raise ValueError
            except (ValueError, AttributeError):
                self._toast(f"File size must be between 0.05 and {MAX_FILE_MB_LIMIT} MB.")
                return None
            ignored = tuple(part.strip() for part in self.ignored_input.text.split(",")
                             if part.strip())
            return ScanConfig(target=self.target,
                              recursive=bool(self.recursive_check.active),
                              ignored_dirs=ignored or DEFAULT_IGNORED_DIRS,
                              max_file_size=int(size_mb * 1024 * 1024))

        def start_scan(self):
            if self.busy:
                return
            config = self._make_config()
            if config is None:
                return
            self._scan_config = config
            self.last_result = None
            self.findings = []
            self.visible_limit = 120
            self._clear_results()
            self.progress.max = 1
            self.progress.value = 0
            self.progress._update_bar()
            self.scan_status.text = "Preparing analysis engine..."
            self.scan_status.color = C_ACCENT
            self._set_busy(True)
            self.task = BackgroundTask(
                lambda cancel, emit: self.engine.run(config, cancel, emit), self.events)
            self.task.start()

        def cancel_scan(self):
            if self.task and self.task.is_alive() and not self.task.cancel_event.is_set():
                self.task.cancel_event.set()
                self.cancel_button.disabled = True
                self.scan_status.text = "Cancelling scan..."

        def _set_busy(self, busy):
            self.busy = busy
            if hasattr(self, "scan_button"):
                self.scan_button.disabled = busy or self.target is None
            if hasattr(self, "cancel_button"):
                self.cancel_button.disabled = not busy

        def _poll_events(self, _dt):
            for _ in range(MAX_EVENTS_PER_TICK):
                try:
                    kind, payload = self.events.get_nowait()
                except queue.Empty:
                    break
                try:
                    self._dispatch(kind, payload)
                except Exception:
                    _write_startup_log("UI_EVENT_FAILED\n" + traceback.format_exc())
                    if hasattr(self, "scan_status"):
                        self.scan_status.text = "Could not display the result. See the error log."

        def _dispatch(self, kind, payload):
            if kind == "status":
                self.scan_status.text = str(payload)
            elif kind == "progress":
                done, total, current = payload
                self.progress.max = max(1, total)
                self.progress.value = done
                self.progress._update_bar()
                if current:
                    self.scan_status.text = f"Scanning {min(done + 1, total)} of {total}: {current}"
                else:
                    self.scan_status.text = f"Scanned {done} of {total} files"
            elif kind == "findings":
                # Keep the canonical list from the final result; this event is
                # only used for fast live feedback on the current scan.
                self.scan_status.text = f"{len(self.findings) + len(payload)} findings detected so far."
            elif kind == "finished":
                self._finish_scan(payload)
            elif kind == "failed":
                self._set_busy(False)
                self.scan_status.text = "Scan failed: " + str(payload)[:350]
                self.scan_status.color = C_RED
                _write_startup_log("SCAN_FAILED\n" + str(payload))
                self._toast("Scan failed. See python_scanner.log for details.")

        def _finish_scan(self, result):
            self._set_busy(False)
            if not isinstance(result, ScanResult):
                self.scan_status.text = "The analysis engine returned an invalid response."
                self.scan_status.color = C_RED
                return
            self.last_result = result
            self.findings = list(result.findings)
            self.progress.max = max(1, result.files_total)
            self.progress.value = result.files_scanned
            self.progress._update_bar()
            self._update_summary(result)
            if result.status is ScanStatus.CANCELLED:
                self.scan_status.text = "Scan cancelled. Results are incomplete."
                self.scan_status.color = C_ORANGE
            elif result.status is ScanStatus.COMPLETED_WITH_ISSUES:
                self.scan_status.text = "Scan finished with some checks unavailable."
                self.scan_status.color = C_ORANGE
            else:
                self.scan_status.text = "Scan completed successfully."
                self.scan_status.color = C_GREEN
            self.export_button.disabled = False
            self._render_findings()
            self._render_tool_status(result)
            self.go("results")
            self.home_files.value_label.text = str(result.files_scanned)
            self.home_findings.value_label.text = str(len(result.findings))
            self.home_latest.text = (
                f"{result.files_scanned} files scanned  •  {len(result.findings)} findings\n"
                f"{result.duration_seconds:.2f} sec  •  {result.status.value}"
            )

        def _update_summary(self, result):
            counts = result.count_by_severity()
            self.result_errors.value_label.text = str(counts[Severity.ERROR])
            self.result_warnings.value_label.text = str(counts[Severity.WARNING])
            self.result_info.value_label.text = str(counts[Severity.INFO])
            notes = result.tool_notes()
            self.results_summary.text = (
                f"Scanned {result.files_scanned} of {result.files_total} files  •  "
                f"{len(result.findings)} findings detected\n"
                f"Duration: {result.duration_seconds:.2f} sec  •  "
                f"Status: {result.status.value}"
                + (f"\n{notes}" if notes else "")
            )
            self.results_summary.color = C_TEXT

        # ----- Findings / detail ---------------------------------------
        def _clear_results(self):
            if not hasattr(self, "findings_list"):
                return
            self.results_summary.text = "No report available yet."
            self.results_summary.color = C_MUTED
            for metric in (self.result_errors, self.result_warnings, self.result_info):
                metric.value_label.text = "—"
            self.findings_list.clear_widgets()
            self.findings_list.add_widget(NeonLabel(text="No findings to display yet.",
                                                    size=11, color=C_MUTED, height=dp(48)))
            self.findings_count.text = "0 findings"
            self.tool_status_label.text = "Tool status will appear here after a scan."
            self.load_more_button.disabled = True

        def _on_filter(self, _spinner, value):
            self.active_filter = value
            self.visible_limit = 120
            self._render_findings()

        def _on_search(self, _widget, value):
            self.search_query = value.strip().lower()
            self.visible_limit = 120
            self._render_findings()

        def _filtered_findings(self):
            severity_map = {"All": "all", "Error": "error", "Warning": "warning", "Info": "info"}
            wanted = severity_map.get(self.active_filter, "all")
            results = []
            for finding in self.findings:
                if wanted != "all" and finding.severity.value != wanted:
                    continue
                haystack = " ".join((finding.tool, finding.rule_id, finding.file,
                                     finding.message, finding.category.value)).lower()
                if self.search_query and self.search_query not in haystack:
                    continue
                results.append(finding)
            return results

        def _render_findings(self):
            if not hasattr(self, "findings_list"):
                return
            self.findings_list.clear_widgets()
            matches = self._filtered_findings()
            shown = matches[:self.visible_limit]
            self.findings_count.text = f"Showing {len(shown)} of {len(matches)} findings"
            if not shown:
                message = "No findings match this filter." if self.findings else "No results yet."
                self.findings_list.add_widget(NeonLabel(text=message, size=11,
                                                        color=C_MUTED, height=dp(54)))
            else:
                for finding in shown:
                    self.findings_list.add_widget(self._finding_card(finding))
            self.load_more_button.disabled = len(matches) <= self.visible_limit

        def _load_more(self):
            self.visible_limit += 120
            self._render_findings()

        def _finding_card(self, finding):
            severity = finding.severity
            accent = C_RED if severity is Severity.ERROR else (
                C_ORANGE if severity is Severity.WARNING else C_BLUE)
            card = NeonSurface(orientation="vertical", padding=dp(12), spacing=dp(5),
                               size_hint_y=None, height=dp(112), fill=C_SURFACE)
            top = BoxLayout(size_hint_y=None, height=dp(24), spacing=dp(7))
            top.add_widget(NeonLabel(text=severity.value.upper(), size=9,
                                     color=accent, bold=True, height=dp(23)))
            top.add_widget(NeonLabel(text=f"{finding.tool}  •  {finding.rule_id}",
                                     size=9, color=C_MUTED, height=dp(23)))
            card.add_widget(top)
            card.add_widget(NeonLabel(text=finding.message, size=10,
                                      color=C_TEXT, height=dp(48)))
            location = finding.file + (f"  :  {finding.line}" if finding.line else "")
            card.add_widget(NeonLabel(text=location, size=9, color=C_MUTED,
                                      height=dp(20)))
            card.bind(on_touch_up=lambda widget, touch, item=finding:
                      self._open_finding(item) if widget.collide_point(*touch.pos) else None)
            return card

        def _suggestion(self, finding):
            suggestions = {
                "SEC-SHELL-TRUE": "Avoid shell=True when possible. Pass subprocess arguments as a list.",
                "SEC-OS-SHELL": "Do not pass untrusted data to shell commands. Prefer direct library APIs.",
                "SEC-PICKLE": "Only load fully trusted pickle data. Prefer a safer interchange format such as JSON for external data.",
                "SEC-DYNAMIC-EXEC": "Do not use eval/exec on external input. Validate input and implement the required logic explicitly.",
                "SEC-YAML-LOAD": "Use yaml.safe_load when parsing untrusted YAML.",
                "SEC-YAML-UNSAFE": "Replace unsafe YAML loading with yaml.safe_load.",
                "SEC-TLS-VERIFY-OFF": "Keep TLS certificate verification enabled.",
                "SEC-SSL-VERIFY-OFF": "Use the default SSL context with certificate validation enabled.",
                "SEC-WEAK-HASH": "Use modern algorithms for security-sensitive hashing. Use a dedicated password-hashing algorithm for passwords.",
                "SEC-TEMPFILE-MKTEMP": "Use tempfile.NamedTemporaryFile or tempfile.mkstemp instead.",
                "SEC-SQL-STRING-FORMAT": "Pass values as database parameters instead of formatting them into SQL strings.",
                "SEC-TAR-EXTRACT": "Validate archive member paths before extraction and allow only paths inside the intended destination.",
                "BUG-MUTABLE-DEFAULT": "Use None as the default and create a fresh list or dictionary inside the function.",
                "BUG-SILENT-EXCEPTION": "Log the error or catch only expected exceptions. A silent pass makes debugging difficult.",
                "BUG-IDENTITY-COMPARE": "Use == or != for value comparison. Reserve is for identity checks, such as comparison with None.",
                "BUG-DUPLICATE-DICT-KEY": "Remove or correct the duplicate key; the earlier value is silently overwritten.",
                "BUG-BLOCKING-SLEEP": "Use await asyncio.sleep(...) inside an async function.",
                "QUALITY-HTTP-NO-TIMEOUT": "Set a timeout for network requests to prevent indefinite waiting.",
                "QUALITY-URLLIB-NO-TIMEOUT": "Set a bounded timeout for urlopen.",
                "QUALITY-ASSERT-STATEMENT": "Use if/raise for required input validation; assert statements may be removed with -O.",
                "QUALITY-FILE-ENCODING": "Specify a text-file encoding, usually encoding='utf-8'.",
                "QUALITY-NONE-COMPARE": "Use value is None or value is not None.",
                "QUALITY-TOO-MANY-ARGS": "Group related parameters in a dataclass or configuration object.",
                "QUALITY-LONG-FUNCTION": "Split the function into smaller functions with clear responsibilities.",
                "QUALITY-COMPLEX-FUNCTION": "Simplify conditional branches and move independent logic into helper functions.",
                "QUALITY-VERY-COMPLEX-FUNCTION": "Break the function into clear paths and add focused tests for important branches.",
                "QUALITY-PRINT-DEBUG": "Use logging for diagnostic events or remove temporary debug output.",
            }
            return suggestions.get(finding.rule_id,
                                   "Review the reported line. Some static-analysis findings may require manual confirmation.")

        def _open_finding(self, finding):
            content = BoxLayout(orientation="vertical", padding=dp(14), spacing=dp(9))
            scroll = ScrollView(do_scroll_x=False, bar_width=dp(3))
            details = BoxLayout(orientation="vertical", size_hint_y=None,
                                spacing=dp(8), padding=(0, 0, 0, dp(10)))
            details.bind(minimum_height=details.setter("height"))
            accent = C_RED if finding.severity is Severity.ERROR else (
                C_ORANGE if finding.severity is Severity.WARNING else C_BLUE)
            details.add_widget(NeonLabel(text=f"{finding.severity.value.upper()}  •  {finding.rule_id}",
                                         size=13, color=accent, bold=True, height=dp(32)))
            details.add_widget(NeonLabel(text=finding.message, size=12,
                                         color=C_TEXT, height=dp(76)))
            details.add_widget(NeonLabel(
                text=f"File: {finding.file}\nLine: {finding.line if finding.line else 'Unknown'}\nTool: {finding.tool}\nCategory: {finding.category.value}\nConfidence: {finding.confidence.value}",
                size=10, color=C_MUTED, height=dp(104)))
            details.add_widget(NeonLabel(text="SUGGESTED FIX", size=12,
                                         color=C_ACCENT, bold=True, height=dp(28)))
            details.add_widget(NeonLabel(text=self._suggestion(finding), size=11,
                                         color=C_TEXT, height=dp(72)))
            if finding.snippet:
                details.add_widget(NeonLabel(text="CODE SNIPPET", size=11,
                                             color=C_ACCENT, bold=True, height=dp(26)))
                details.add_widget(NeonLabel(text=finding.snippet, size=10,
                                             color=C_MUTED, height=dp(66)))
            scroll.add_widget(details)
            content.add_widget(scroll)
            popup = Popup(title="Finding Details", content=content,
                          size_hint=(0.94, 0.82), separator_color=C_ACCENT)
            content.add_widget(self._button("CLOSE", popup.dismiss,
                                            secondary=True, height=44))
            self._finding_popup = popup
            popup.open()

        def _render_tool_status(self, result):
            state_names = {
                ToolState.OK: "Available",
                ToolState.MISSING: "Not installed",
                ToolState.SKIPPED: "Not run",
                ToolState.TIMEOUT: "Timed out",
                ToolState.FAILED: "Failed",
            }
            lines = []
            for tool in result.tool_statuses:
                line = f"{tool.name}: {state_names.get(tool.state, tool.state.value)}"
                if tool.version:
                    line += f"  ({tool.version})"
                if tool.detail and tool.state is not ToolState.OK:
                    line += f"\n{redact_text(tool.detail)[:160]}"
                lines.append(line)
            self.tool_status_label.text = "\n".join(lines) if lines else "Tool status unavailable."

        # ----- Report export --------------------------------------------
        def export_report(self):
            if not self.last_result:
                self._toast("There is no report to export yet.")
                return
            form = BoxLayout(orientation="vertical", padding=dp(14), spacing=dp(10))
            name_field = TextInput(text="python_scanner_report.json", multiline=False,
                                   size_hint_y=None, height=dp(46),
                                   background_normal="", background_active="",
                                   background_color=C_SURFACE_2,
                                   foreground_color=C_TEXT, cursor_color=C_ACCENT,
                                   font_size=sp(12))
            form.add_widget(NeonLabel(text="Report filename", size=11, color=C_MUTED))
            form.add_widget(name_field)
            form.add_widget(NeonLabel(
                text="The report may contain messages and masked code snippets. Review it before sharing.",
                size=10, color=C_MUTED, height=dp(42)))
            popup = Popup(title="Export Report", content=form,
                          size_hint=(0.92, 0.40), separator_color=C_ACCENT)
            actions = GridLayout(cols=2, spacing=dp(8), size_hint_y=None, height=dp(48))

            def save(*_):
                name = Path(name_field.text.strip()).name
                if not name:
                    self._toast("Enter a filename.")
                    return
                if not name.lower().endswith(".json"):
                    name += ".json"
                destination_dir = _writable_report_folder()
                destination = destination_dir / name
                try:
                    write_json_report(self.last_result, destination)
                except Exception as exc:
                    _write_startup_log("REPORT_EXPORT_FAILED\n" + traceback.format_exc())
                    self._toast(f"Report export failed: {type(exc).__name__}")
                else:
                    popup.dismiss()
                    self._toast(f"Report saved:\n{destination}")

            actions.add_widget(self._button("CANCEL", popup.dismiss, secondary=True))
            actions.add_widget(self._button("SAVE", save))
            form.add_widget(actions)
            popup.open()

        # ----- Small UX helpers ----------------------------------------
        def _toast(self, message):
            try:
                if self._toast_popup:
                    self._toast_popup.dismiss()
                label = NeonLabel(text=str(message), size=11, color=C_TEXT,
                                  halign="center", height=dp(74))
                popup = Popup(title=APP_TITLE, content=label,
                              size_hint=(0.90, 0.30), separator_color=C_ACCENT)
                self._toast_popup = popup
                popup.open()
                Clock.schedule_once(lambda _dt: popup.dismiss(), 3.0)
            except Exception:
                _write_startup_log("TOAST_FAILED\n" + traceback.format_exc())

        def on_pause(self):
            return True

        def on_stop(self):
            if self.task and self.task.is_alive():
                self.task.cancel_event.set()


def _writable_report_folder() -> Path:
    for folder in (Path("/storage/emulated/0/Download"), Path.home(), Path.cwd()):
        try:
            if folder.is_dir() and os.access(str(folder), os.W_OK):
                return folder
        except OSError:
            continue
    return Path.cwd()


def main() -> int:
    if not KIVY_AVAILABLE:
        _write_startup_log("KIVY_NOT_AVAILABLE\n" + KIVY_IMPORT_ERROR)
        print("Kivy must be installed and enabled in Pydroid 3 to run the mobile interface.\n"
              + KIVY_IMPORT_ERROR, file=sys.stderr)
        return 2
    try:
        PythonScannerApp().run()
        return 0
    except Exception:
        detail = traceback.format_exc()
        _write_startup_log("APPLICATION_START_FAILED\n" + detail)
        print("Python Scanner could not start. See python_scanner.log.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

