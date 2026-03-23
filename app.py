"""NanoHound slim launcher.

Initializes the UI and starts the NiceGUI server. The heavy UI
implementation lives in `ui._app_impl` and is assembled via
`ui.layout.build_ui()`.
"""

from __future__ import annotations

from nicegui import ui

from ui.layout import build_ui


def main() -> None:
    build_ui()
    ui.run(title="NanoHound", reload=False)


if __name__ == "__main__":
    main()
