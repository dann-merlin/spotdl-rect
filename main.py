#!/usr/bin/env python3

from enum import Enum
from functools import cache
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
from pathlib import Path
from subprocess import run
from threading import Lock, Thread
from readerwriterlock.rwlock import RWLockFair
from typing import Any, override
from urllib.parse import parse_qs, urlparse
import re
import json
import tomllib

DEFAULTS: dict[str, str] = {
    "output_dir": './out',
    "spotify_cache_path": './spotify.cache',
    "spotdl_save_file": "./save.spotdl",
    "listen_ip": "127.0.0.1",
}

def load_config(config_file: str = "config.toml") -> dict[str, str]:
    config_data: dict[str, str] = {}

    try:
        with open(config_file, 'rb') as f:
            parsed = tomllib.load(f)
    except FileNotFoundError:
        parsed: dict[str, str] = {}

    for key, default in DEFAULTS.items():
        value = parsed.get(key, default)
        config_data[key] = value
    return config_data

config = load_config()

OUTPUT_PATH_FORMAT = Path(config['output_dir']) / '{album-artist}/{album}/{track-number}-{title}.{output-ext}'

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

log = logging.getLogger('SpotDL-Rect')

spotify_path_re = re.compile(r"^/(artist|track|album|playlist)/[A-Za-z0-9]+$")
def is_valid_path_check(path: str) -> bool:
    return bool(spotify_path_re.match(path))

@cache
def get_html_file():
    html_path = Path('result.html')
    assert html_path.exists()
    return html_path.read_text()

@cache
def get_css_file():
    css_path = Path('style.css')
    assert css_path.exists()
    return css_path.read_text()

class JsonEnum(str, Enum):
    @override
    def __str__(self) -> str:
        return self.value

    def __json__(self) -> str:
        return self.value

class StateEnum(JsonEnum):
    ongoing = 'ongoing'
    done = 'done'
    error = 'error'

class SpotDLRectState:
    def __init__(self) -> None:
        self.errored: set[str] = set()
        self.done: set[str] = set()
        self.lock: RWLockFair = RWLockFair()

    def get_state_for_target(self, target: str) -> StateEnum:
        with self.lock.gen_rlock():
            if target in self.done:
                return StateEnum.done
            if target in self.errored:
                return StateEnum.error
            return StateEnum.ongoing

    def set_error(self, target: str):
        with self.lock.gen_wlock():
            self.errored.add(target)

    def set_done(self, target: str):
        with self.lock.gen_wlock():
            self.done.add(target)

    def is_known(self, target: str) -> bool:
        with self.lock.gen_rlock():
            return target in self.done or target in self.errored

states = SpotDLRectState()

add_lock = Lock()
def try_add(path: str):
    with add_lock:
        if states.is_known(path):
            return
        spotify_link = 'https://open.spotify.com' + path
        proc = run([
            'spotdl',
            '--cache-path', config['spotify_cache_path'],
            '--use-cache-file',
            '--scan-for-songs',
            '--overwrite', 'skip',
            '--fetch-albums',
            '--save-file', config['spotdl_save_file'],
            '--create-skip-file', '--respect-skip-file',
            '--output', str(OUTPUT_PATH_FORMAT),
            'download', spotify_link
        ])
        if proc.returncode != 0:
            states.set_error(path)
            return
        states.set_done(path)


class SpotDLRectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/favicon.ico':
            self.send_favicon()
            return
        if parsed.path == '/style.css':
            self.send_css()
            return
        self.send_html(get_html_file())
        if is_valid_path_check(parsed.path):
            Thread(target=try_add, args=(parsed.path,), daemon=False).start()

    def do_POST(self):
        parsed = urlparse(self.path)
        queries = parse_qs(parsed.query)
        log.info('POST: ' + parsed.query)
        if parsed.path != '/status':
            self.send_error(404, 'Invalid path')
            return
        targets = queries.get('req')
        log.info('POST: ' + str(targets))
        if not targets or len(targets) != 1:
            self.send_error(422, 'You need to specify exactly one req param.')
            return
        target = targets[0]
        if not is_valid_path_check(target):
            self.send_error(422, 'This is not a valid target')
            return
        self.send_status_for(target)

    def send_status_for(self, target: str):
        state = states.get_state_for_target(target)
        self.send_json({
            'status': state
        })

    def send_json(self, json_dict: dict[str, Any]):  # pyright:ignore[reportExplicitAny]
        dump: bytes = json.dumps(json_dict).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.end_headers()
        written_bytes = self.wfile.write(dump)
        self.written_bytes_check('status', written_bytes, len(dump))

    def send_favicon(self):
        favicon_path = Path('./logo.png')
        if not favicon_path.exists():
            self.send_error(404, 'Not configured')
            return
        favicon_bytes = favicon_path.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', 'image/png')
        self.send_header('Content-Length', str(len(favicon_bytes)))
        self.end_headers()
        written_bytes = self.wfile.write(favicon_bytes)
        self.written_bytes_check('favicon', written_bytes, len(favicon_bytes))

    def send_css(self):
        css = get_css_file()
        self.send_response(200)
        self.send_header('Content-Type', 'text/css; charset=utf-8')
        self.end_headers()
        encoded_css = css.encode('utf-8')
        written_bytes = self.wfile.write(encoded_css)
        self.written_bytes_check('encoded css', written_bytes, len(encoded_css))

    def written_bytes_check(self, object_name: str, written: int, expected: int):
        if written != expected:
            log.warning(f'Failed to write {object_name}.'
                + f'Only {written} out of {expected}'
                + 'bytes were written.')

    def send_html(self, html: str, status: int = 200):
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        encoded_html = html.encode('utf-8')
        written_bytes = self.wfile.write(encoded_html)
        self.written_bytes_check('encoded html', written_bytes, len(encoded_html))

def start_server(ip: str, port: int):
    server = HTTPServer((ip, port), SpotDLRectHandler)
    log.info(f"Listening on http://{ip}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Stopping gracefully...")
        exit(0)


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    start_server(config['listen_ip'], 8080)
