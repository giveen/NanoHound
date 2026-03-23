#!/usr/bin/env python3
import asyncio
import json
import os
import tempfile
from playwright.async_api import async_playwright

async def main():
    # create a tiny users.json to upload
    fd, path = tempfile.mkstemp(suffix='users.json', prefix='pw_upload_')
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump({"data": [{"ObjectIdentifier": "S-1-5-21-9999-1000", "Properties": {"name": "PLAY\\tester", "samaccountname": "tester"}}]}, f)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
        page = await browser.new_page()
        page.set_default_timeout(30000)
        print('navigating to http://127.0.0.1:8080/')
        await page.goto('http://127.0.0.1:8080/')
        print('waiting for file input (attached)')
        await page.wait_for_selector('input[type=file]', timeout=15000, state='attached')
        print('setting input files to', path)
        # ensure the uploaded filename is exactly 'users.json' so the ingestor recognizes it
        with open(path, 'rb') as fh:
            data = fh.read()
        await page.set_input_files('input[type=file]', [{
            'name': 'users.json',
            'mimeType': 'application/json',
            'buffer': data,
        }])
        # wait for a notification or some DOM change indicating ingest
        try:
            # wait for the status label element to be present (may be hidden)
            await page.wait_for_selector('text=Loaded', timeout=20000, state='attached')
            print('upload: status seen (Loaded - attached)')
        except Exception as e:
            print('upload: status not seen (timeout)', str(e))
        await browser.close()
    try:
        os.remove(path)
    except Exception:
        pass

if __name__ == '__main__':
    asyncio.run(main())
