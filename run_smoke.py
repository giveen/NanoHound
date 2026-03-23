#!/usr/bin/env python3
import asyncio, io, zipfile, json
from nicegui import ui
from ui.layout import build_ui

# Build UI (populates impl.path_source_input/path_target_input)
build_ui()

import ui._app_impl as impl

# create a minimal sharphound zip in memory
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as z:
    z.writestr('users.json', json.dumps({'data':[{'ObjectIdentifier':'S-1-5-21-9999-1000','Properties':{'name':'PLAY\\tester','samaccountname':'tester'}}]}))
buf.seek(0)
zip_bytes = buf.read()

class FakeFile:
    def __init__(self, name, data):
        self.name = name
        self._data = data
    def read(self):
        return self._data

class FakeEvent:
    def __init__(self, f):
        self.file = f

fake = FakeEvent(FakeFile('sharphound.zip', zip_bytes))

print('Calling handle_upload...')
def _schedule_ingest():
    # Perform ingestion here inside NiceGUI's slot so UI notifications
    # and widget updates are valid. This mirrors the core steps from
    # `handle_upload()` but runs synchronously in the UI context.
    import tempfile, pathlib

    try:
        tf = tempfile.NamedTemporaryFile(delete=False, suffix='.zip', prefix='nh_upload_')
        try:
            tf.write(zip_bytes)
            tf.flush()
        finally:
            tf.close()

        temp_path = pathlib.Path(tf.name)
        parsed = impl.ingestor.unzip_and_parse(temp_path)

        for dataset in impl.loaded_data:
            if parsed.get(dataset):
                impl.loaded_data[dataset] = parsed[dataset]

        impl.graph_engine.build_from_sharphound(impl.loaded_data)
        impl.highlighted_manual_path.clear()
        impl._autofill_path_inputs()
        impl._refresh_chart()
        impl._recalculate_live_path(notify_when_missing=True)
        if impl.loot_refresh_callback:
            impl.loot_refresh_callback()
        impl._set_status(
            f"Loaded {impl.graph_engine.graph.number_of_nodes()} nodes / {impl.graph_engine.graph.number_of_edges()} edges"
        )
        ui.notify("SharpHound data ingested", color="positive")
    except Exception as exc:
        ui.notify(f"Ingestion failed: {exc}", color="negative")
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass

ui.timer(0.1, _schedule_ingest, once=True)

# Start the server for manual inspection (ingest runs shortly after startup)
print('Starting UI server; ingestion will run shortly...')
ui.run(title='NanoHound Smoke', reload=False)
