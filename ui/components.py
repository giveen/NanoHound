"""Reusable NiceGUI components."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Any

from nicegui import events, ui


def create_notes_panel(
    get_note: Callable[[str], str],
    set_note: Callable[[str, str], None],
) -> Callable[[str, str], None]:
    """Build the per-node notes editor inside the current NiceGUI context.

    Returns ``update_notes_panel(sid, node_label) -> None`` — call this whenever
    the user selects a node to load that node's note into the textarea.
    """
    # Mutable container so the lambda can close over the *current* SID.
    current_sid: list[str] = [""]

    node_header = ui.label("Select a node to write notes").classes(
        "text-gray-100 text-xs italic mb-1"
    )

    def _on_change(e: events.ValueChangeEventArguments) -> None:
        sid = current_sid[0]
        if sid:
            set_note(sid, e.value or "")

    notes_area = (
        ui.textarea(
            label="Node Notes",
            placeholder="Write intelligence notes about this node…",
            on_change=_on_change,
        )
        .props("autogrow outlined dark")
        .classes("w-full text-white")
    )

    def update_notes_panel(sid: str, node_label: str) -> None:
        """Switch the editor to the given node without triggering a save."""
        current_sid[0] = sid
        node_header.text = f"Notes: {node_label}"
        # Assign value directly – NiceGUI programmatic updates do not fire
        # the on_change callback, so no spurious write occurs here.
        notes_area.value = get_note(sid)

    return update_notes_panel


def create_upload_dropzone(
    on_upload: Callable[[events.UploadEventArguments], None | Coroutine[Any, Any, None]],
):
    """Create the SharpHound upload control."""
    return (
        ui.upload(
            label="Drop SharpHound zip or JSON files",
            auto_upload=True,
            multiple=False,
            on_upload=on_upload,
        )
        .props("accept=.zip,.json")
        .classes(
            "w-full max-w-2xl bg-zinc-900 text-white border border-zinc-700 "
            "rounded-xl p-3"
        )
    )


def create_search_bar(on_search: Callable[[str, str], None]):
    """Create the source/target shortest path search UI."""
    with ui.row().classes("w-full items-end gap-3"):
        source_input = ui.input("Source (SID or Name)").classes("w-full text-white")
        target_input = ui.input("Target (SID or Name)").classes("w-full text-white")
        ui.button(
            "Find Attack Path",
            on_click=lambda: on_search(source_input.value or "", target_input.value or ""),
        ).classes("bg-red-700 text-white")

    return source_input, target_input


def create_loot_table_tab(
    on_upsert: Callable[[dict[str, str]], None],
    on_import: Callable[[str], int],
    get_rows: Callable[[], list[dict[str, str]]],
) -> Callable[[], None]:
    """Build a Loot Table tab and return a refresh callback."""
    columns = [
        {"name": "principal", "label": "Principal", "field": "principal", "align": "left"},
        {"name": "username", "label": "Username", "field": "username", "align": "left"},
        {"name": "domain", "label": "Domain", "field": "domain", "align": "left"},
        {"name": "password", "label": "Password", "field": "password", "align": "left"},
        {"name": "ntlm_hash", "label": "NTLM Hash", "field": "ntlm_hash", "align": "left"},
        {"name": "kerberos_ticket", "label": "Kerberos", "field": "kerberos_ticket", "align": "left"},
        {"name": "source", "label": "Source", "field": "source", "align": "left"},
    ]
    table = ui.table(columns=columns, rows=[], row_key="principal").classes("w-full")

    with ui.row().classes("w-full gap-3 items-end"):
        principal_input = ui.input("Principal (SID or DOMAIN\\username)").classes("w-full")
        username_input = ui.input("Username").classes("w-52")
        domain_input = ui.input("Domain").classes("w-52")

    with ui.row().classes("w-full gap-3 items-end"):
        password_input = ui.input("Password").props("type=password").classes("w-full")
        ntlm_input = ui.input("NTLM Hash").classes("w-full")
        ticket_input = ui.input("Kerberos Ticket/CCACHE path").classes("w-full")

    def refresh_table() -> None:
        table.rows = get_rows()
        table.update()

    def save_row() -> None:
        payload = {
            "principal": principal_input.value or "",
            "username": username_input.value or "",
            "domain": domain_input.value or "",
            "password": password_input.value or "",
            "ntlm_hash": ntlm_input.value or "",
            "kerberos_ticket": ticket_input.value or "",
        }
        on_upsert(payload)
        refresh_table()

    def clear_form() -> None:
        principal_input.value = ""
        username_input.value = ""
        domain_input.value = ""
        password_input.value = ""
        ntlm_input.value = ""
        ticket_input.value = ""

    with ui.dialog() as import_dialog, ui.card().classes("w-[760px] bg-zinc-900 text-white"):
        ui.label("Import Secrets (secretsdump / crackmapexec grepable)").classes("text-white")
        import_text = ui.textarea(
            "Paste output",
            placeholder="DOMAIN\\user:RID:LMHASH:NTHASH::: or DOMAIN\\user:password",
        ).props("autogrow").classes("w-full")
        with ui.row().classes("w-full justify-end gap-2"):
            ui.button("Cancel", on_click=import_dialog.close).props("flat").classes("text-white")

            def run_import() -> None:
                count = on_import(import_text.value or "")
                import_dialog.close()
                refresh_table()
                ui.notify(f"Imported {count} credential entries", color="positive")

            ui.button("Import", on_click=run_import).classes("bg-red-700 text-white")

    with ui.row().classes("w-full gap-2"):
        ui.button("Save / Update Credential", on_click=save_row).classes("bg-red-700 text-white")
        ui.button("Clear Form", on_click=clear_form).props("outline").classes("text-white")
        ui.button("Import Secrets", on_click=import_dialog.open).props("outline").classes("text-white")
        ui.button("Refresh", on_click=refresh_table).props("flat").classes("text-white")

    refresh_table()
    return refresh_table
