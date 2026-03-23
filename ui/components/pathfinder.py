from __future__ import annotations

from typing import Any, Callable
from nicegui import ui


def create_pathfinder(on_find_path: Callable[[str, str], None]) -> tuple[Any, Any, Callable[[], None]]:
    """Create source/target inputs and a Find Path button.

    Returns (source_input, target_input, refresh_fn).
    """
    with ui.row().classes("w-full items-end gap-3"):
        source_input = ui.input("Source (SID or Name)").classes("w-full text-white")
        target_input = ui.input("Target (SID or Name)").classes("w-full text-white")
        ui.button("Find Attack Path", on_click=lambda: on_find_path(source_input.value or "", target_input.value or "")).classes("bg-red-700 text-white")

    def _refresh() -> None:
        source_input.update()
        target_input.update()

    return source_input, target_input, _refresh
