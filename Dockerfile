# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm
WORKDIR /app
COPY --chmod=644 <<'SHINWOL_REQUIREMENTS_END' /app/requirements.txt
fastapi==0.141.1
uvicorn==0.52.1
websockets==16.0
httpx==0.28.1
SHINWOL_REQUIREMENTS_END
COPY --chmod=644 <<'SHINWOL_GATEWAY_END' /app/gateway.py
"""Authenticated noVNC and CDP gateway. Browser/VNC ports stay on loopback.

No Naver credentials or screenshots are recorded here. CDP is disabled until
the user hands control over; manual control revokes automation access.
"""
import asyncio
import contextlib
import hmac
import os
import json
import base64
import secrets
import time
from urllib.parse import urlsplit

import httpx
import websockets
from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse, Response, RedirectResponse
from fastapi.staticfiles import StaticFiles


def create_app():
    origin = os.environ['SHINWOL_PUBLIC_ORIGIN'].rstrip('/')
    token = os.environ['SHINWOL_CONTROL_TOKEN']
    dev = os.environ.get('SHINWOL_LOCAL_TEST') == '1'
    parsed = urlsplit(origin)
    if len(token) < 32:
        raise RuntimeError('Control token must contain at least 32 characters')
    if parsed.scheme != 'https' and not (dev and parsed.hostname in ('127.0.0.1', 'localhost')):
        raise RuntimeError('HTTPS origin required')
    if parsed.path or parsed.query or parsed.fragment or parsed.username:
        raise RuntimeError('Origin must contain only scheme, hostname, and optional port')
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.automation = False
    app.state.active = set()
    app.state.mode_lock = asyncio.Lock()
    sessions = {}
    failures = []
    cookie_name = 'shinwol_local' if dev else '__Host-shinwol'

    def signed_in(connection):
        session = connection.cookies.get(cookie_name, '')
        return sessions.get(session, 0) > time.time()

    def same_origin(connection):
        return connection.headers.get('origin') == origin

    def bearer(connection):
        expected = 'Bearer ' + token
        return hmac.compare_digest(connection.headers.get('authorization', ''), expected)

    @app.middleware('http')
    async def protect(request, call_next):
        if request.headers.get('host') != parsed.netloc:
            return JSONResponse({'error': 'invalid host'}, status_code=400)
        if request.url.path.startswith('/novnc') and not signed_in(request):
            return JSONResponse({'error': 'authentication required'}, status_code=401)
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
            f"connect-src 'self' {'ws' if dev else 'wss'}://{parsed.netloc}; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        )
        return response

    @app.get('/health')
    async def health():
        try:
            async with httpx.AsyncClient(trust_env=False) as client:
                response = await client.get('http://127.0.0.1:9222/json/version', timeout=2)
                response.raise_for_status()
            return {'ready': True}
        except Exception:
            return JSONResponse({'ready': False}, status_code=503)

    @app.get('/')
    async def home(request: Request):
        if not signed_in(request):
            return HTMLResponse('''<!doctype html><html lang="ko"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>신월농원 브라우저 접속</title>
<h1>신월농원 브라우저 접속</h1><p>서버에 설정한 접속 키를 입력하세요. 네이버 비밀번호를 입력하는 곳이 아닙니다.</p>
<form id="login"><input type="password" id="key" autocomplete="off" required><button>접속</button></form><p id="error"></p>
<script>document.querySelector('form').onsubmit=async e=>{e.preventDefault();const r=await fetch('/session',
{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:document.querySelector('#key').value})});
document.querySelector('#key').value='';if(r.ok)location.reload();else document.querySelector('#error').textContent='접속 실패';};</script></html>''')
        return HTMLResponse('''<!doctype html><html lang="ko"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>신월농원 로그인 브라우저</title>
<h1>네이버 직접 로그인</h1><p>수동 조작 중에는 자동화 연결을 허용하지 않습니다. 로그인 후 제어를 넘겨주세요.</p>
<button onclick="mode('manual')">직접 조작 시작</button>
<button onclick="mode('automation')">로그인 완료 · 자동화에 제어 넘기기</button>
<button onclick="logout()">접속 종료</button><p id="status"></p>
<a id="screen" target="_blank" rel="noopener" hidden href="/screen">브라우저 화면 열기</a>
<script>async function mode(mode){const r=await fetch('/mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode})});
document.querySelector('#status').textContent=r.ok?(mode==='manual'?'직접 조작 중':'자동화에 제어를 넘겼습니다'):'변경 실패';
document.querySelector('#screen').hidden=!r.ok||mode!=='manual';}
async function logout(){await fetch('/logout',{method:'POST'});location.reload();}</script></html>''')

    @app.post('/session')
    async def login(request: Request):
        if not same_origin(request):
            return JSONResponse({'error': 'origin'}, status_code=403)
        now = time.time()
        failures[:] = [t for t in failures if now - t < 600]
        if len(failures) >= 5:
            return JSONResponse({'error': 'retry later'}, status_code=429)
        try:
            candidate = (await request.json()).get('key', '')
        except Exception:
            candidate = ''
        if not isinstance(candidate, str) or not hmac.compare_digest(candidate.encode(), token.encode()):
            failures.append(now)
            return JSONResponse({'error': 'authentication'}, status_code=401)
        for stale in [key for key, expiry in sessions.items() if expiry <= now]:
            sessions.pop(stale, None)
        sid = secrets.token_urlsafe(32)
        sessions[sid] = now + 1800
        response = JSONResponse({'ok': True})
        response.set_cookie(cookie_name, sid, max_age=1800, httponly=True,
                            secure=not dev, samesite='strict', path='/')
        return response

    async def change_mode(automation):
        async with app.state.mode_lock:
            app.state.automation = automation
            # Revoke existing sockets before allowing the other control mode.
            for ws in list(app.state.active):
                with contextlib.suppress(Exception):
                    await ws.close(code=1000)

    @app.post('/mode')
    async def mode(request: Request):
        if not signed_in(request) or not same_origin(request):
            return JSONResponse({'error': 'unauthorized'}, status_code=403)
        value = (await request.json()).get('mode')
        if value not in ('manual', 'automation'):
            return JSONResponse({'error': 'mode'}, status_code=400)
        await change_mode(value == 'automation')
        return {'mode': value}

    @app.post('/logout')
    async def logout(request: Request):
        if not signed_in(request) or not same_origin(request):
            return JSONResponse({'error': 'unauthorized'}, status_code=403)
        sessions.pop(request.cookies.get(cookie_name), None)
        await change_mode(False)
        response = JSONResponse({'ok': True})
        response.delete_cookie(cookie_name, secure=not dev, httponly=True, samesite='strict')
        return response

    @app.websocket('/{channel}')
    async def tunnel(ws: WebSocket, channel: str):
        if ws.headers.get('host') != parsed.netloc:
            await ws.close(code=1008)
            return
        allowed = False
        if channel == 'vnc':
            allowed = signed_in(ws) and same_origin(ws) and not app.state.automation
        elif channel == 'cdp':
            allowed = bearer(ws) and app.state.automation and ws.headers.get('origin') in (None, origin)
        if not allowed:
            await ws.close(code=1008)
            return
        # Recheck and register under the mode lock to avoid a handoff race.
        async with app.state.mode_lock:
            if (channel == 'cdp') != app.state.automation:
                await ws.close(code=1008)
                return
            await ws.accept(subprotocol='binary' if 'binary' in ws.scope.get('subprotocols', []) else None)
            app.state.active.add(ws)
        try:
            if channel == 'vnc':
                reader, writer = await asyncio.open_connection('127.0.0.1', 5900)
                async def to_vnc():
                    while True:
                        message = await ws.receive()
                        if message['type'] == 'websocket.disconnect' or not signed_in(ws):
                            return
                        data = message.get('bytes')
                        if data is None:
                            return
                        writer.write(data)
                        await writer.drain()

                async def from_vnc():
                    while signed_in(ws):
                        data = await reader.read(65536)
                        if not data:
                            return
                        await ws.send_bytes(data)

                tasks = [asyncio.create_task(to_vnc()), asyncio.create_task(from_vnc())]
                try:
                    # Bound an unattended screen session to ten minutes.
                    # This limits one session, not the workspace's total bill.
                    await asyncio.wait(tasks, timeout=600, return_when=asyncio.FIRST_COMPLETED)
                finally:
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
                    writer.close()
                    await writer.wait_closed()
                return
            if channel == 'cdp':
                async with httpx.AsyncClient(trust_env=False) as client:
                    r = await client.get('http://127.0.0.1:9222/json/version', timeout=5)
                    r.raise_for_status()
                    target = r.json()['webSocketDebuggerUrl']
                address = urlsplit(target)
                if address.hostname not in ('localhost', '127.0.0.1') or address.port != 9222:
                    raise RuntimeError('Unexpected browser endpoint')
            async with websockets.connect(target, proxy=None, max_size=32*1024*1024) as upstream:
                async def outgoing():
                    while True:
                        if channel == 'vnc' and not signed_in(ws):
                            return
                        message = await ws.receive()
                        if channel == 'vnc' and not signed_in(ws):
                            return
                        if message['type'] == 'websocket.disconnect':
                            return
                        await upstream.send(message.get('bytes') if message.get('bytes') is not None else message['text'])

                async def incoming():
                    async for message in upstream:
                        if channel == 'vnc' and not signed_in(ws):
                            return
                        await (ws.send_bytes(message) if isinstance(message, bytes) else ws.send_text(message))

                tasks = [asyncio.create_task(outgoing()), asyncio.create_task(incoming())]
                try:
                    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                finally:
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
        except Exception:
            # Never log CDP payloads, session cookies, URLs or browser contents.
            with contextlib.suppress(Exception):
                await ws.close(code=1011)
        finally:
            app.state.active.discard(ws)
            with contextlib.suppress(Exception):
                await ws.close()

    screen_lock = asyncio.Lock()

    async def screen_command(method, params=None):
        # Only standard browser CDP commands; never Naver's internal APIs/models.
        async with httpx.AsyncClient(trust_env=False) as client:
            r = await client.get('http://127.0.0.1:9222/json/list', timeout=5)
            pages = [p for p in r.json() if p.get('type') == 'page']
        if not pages:
            raise RuntimeError('No browser tab')
        endpoint = pages[0]['webSocketDebuggerUrl']
        address = urlsplit(endpoint)
        if address.hostname not in ('localhost', '127.0.0.1') or address.port != 9222:
            raise RuntimeError('Unexpected browser address')
        async with websockets.connect(endpoint, proxy=None, max_size=8*1024*1024) as channel:
            await channel.send(json.dumps({'id': 1, 'method': method, 'params': params or {}}))
            while True:
                message = json.loads(await asyncio.wait_for(channel.recv(), 10))
                if message.get('id') == 1:
                    if 'error' in message:
                        raise RuntimeError('Browser command failed')
                    return message.get('result', {})

    def manual_user(request):
        return signed_in(request) and not app.state.automation

    @app.get('/screen')
    async def screen(request: Request):
        if not manual_user(request):
            return JSONResponse({'error': 'manual authenticated session required'}, status_code=403)
        return HTMLResponse('''<!doctype html><html lang="ko"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>네이버 직접 로그인</title>
<style>body{font-family:sans-serif;margin:12px}img{width:100%;border:1px solid #aaa;touch-action:manipulation}textarea{width:95%;font-size:18px}button{padding:10px;margin:4px}</style>
<h2>네이버 직접 로그인</h2><p>사진 화면을 눌러 입력 위치를 선택한 다음 아래 입력란을 사용하세요. 입력값은 기록하지 않습니다. 화면은 10분 후 멈춥니다.</p>
<button onclick="send('navigate')">네이버 글쓰기 열기</button><button onclick="send('key',{key:'Tab'})">다음 입력칸</button><button onclick="send('key',{key:'Enter'})">Enter</button><button onclick="send('key',{key:'Backspace'})">한 글자 지우기</button>
<p id="state">화면 연결 중</p><img id="view" alt="현재 Chrome 화면"><br>
<label><input type="checkbox" id="secret" onchange="changeType()" checked>입력 내용 가리기</label>
<input type="password" id="text" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="선택한 네이버 입력칸에 보낼 내용" style="width:95%;font-size:18px">
<button onclick="typeText()">선택한 칸에 입력</button><button onclick="send('scroll',{delta:550})">아래로</button><button onclick="send('scroll',{delta:-550})">위로</button>
<p>로그인이 끝나면 이 탭을 닫고 원래 제어 페이지에서 ‘로그인 완료 · 자동화에 제어 넘기기’를 누르세요.</p>
<script>
const view=document.querySelector('#view'),state=document.querySelector('#state');let url=null,stopped=false;
async function send(action,data={}){const r=await fetch('/screen/input',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action,...data})});if(!r.ok)state.textContent='조작 실패: 수동 모드와 로그인을 확인하세요.';}
async function typeText(){const box=document.querySelector('#text');const value=box.value;box.value='';if(value)await send('text',{text:value});}
function changeType(){document.querySelector('#text').type=document.querySelector('#secret').checked?'password':'text';}
view.onclick=e=>{const b=view.getBoundingClientRect();send('click',{x:(e.clientX-b.left)*view.naturalWidth/b.width,y:(e.clientY-b.top)*view.naturalHeight/b.height});};
async function refresh(){if(stopped)return;try{const r=await fetch('/screen/frame');if(!r.ok){state.textContent='화면 중지: 수동 모드와 로그인을 확인하세요.';stopped=true;return;}const next=URL.createObjectURL(await r.blob());view.src=next;if(url)URL.revokeObjectURL(url);url=next;state.textContent='현재 Chrome 주소: '+(r.headers.get('X-Browser-Origin')||'확인 중');}catch(e){state.textContent='연결 재확인 중';}if(!stopped)setTimeout(refresh,1500);}
setTimeout(()=>{stopped=true;document.querySelector('#text').value='';state.textContent='10분이 지나 화면 갱신을 멈췄습니다. 필요하면 새로고침하세요.';},600000);refresh();
</script></html>''')

    @app.get('/screen/frame')
    async def screen_frame(request: Request):
        async with app.state.mode_lock:
            if not manual_user(request):
                return JSONResponse({'error': 'manual session required'}, status_code=403)
            async with screen_lock:
                try:
                    tree = await screen_command('Page.getFrameTree')
                    current = urlsplit(tree['frameTree']['frame']['url'])
                    shown_origin = current.scheme + '://' + current.hostname if current.hostname else 'about:blank'
                    result = await screen_command('Page.captureScreenshot', {'format': 'jpeg', 'quality': 45})
                    return Response(base64.b64decode(result['data']), media_type='image/jpeg',
                                    headers={'X-Browser-Origin': shown_origin})
                except Exception:
                    return JSONResponse({'error': 'browser frame unavailable'}, status_code=503)

    @app.post('/screen/input')
    async def screen_input(request: Request):
        async with app.state.mode_lock:
            if not manual_user(request) or not same_origin(request):
                return JSONResponse({'error': 'manual authenticated origin required'}, status_code=403)
            if len(await request.body()) > 20000:
                return JSONResponse({'error': 'input too large'}, status_code=413)
            data = await request.json()
            action = data.get('action')
            async with screen_lock:
                try:
                    if action == 'navigate':
                        await screen_command('Page.navigate', {'url': 'https://blog.naver.com/dividendwhisky/postwrite'})
                    elif action == 'text' and isinstance(data.get('text'), str) and len(data['text']) <= 4096:
                        await screen_command('Input.insertText', {'text': data['text']})
                    elif action == 'click':
                        x, y = float(data['x']), float(data['y'])
                        if not (0 <= x <= 4096 and 0 <= y <= 4096):
                            return JSONResponse({'error': 'coordinates'}, status_code=400)
                        for event in ('mousePressed', 'mouseReleased'):
                            await screen_command('Input.dispatchMouseEvent', {'type': event, 'x': x, 'y': y,
                                'button': 'left', 'clickCount': 1})
                    elif action == 'key' and data.get('key') in ('Tab', 'Enter', 'Backspace'):
                        code = {'Tab': 9, 'Enter': 13, 'Backspace': 8}[data['key']]
                        for event in ('keyDown', 'keyUp'):
                            await screen_command('Input.dispatchKeyEvent', {'type': event, 'key': data['key'],
                                'code': data['key'], 'windowsVirtualKeyCode': code,
                                **({'text': '\r'} if data['key'] == 'Enter' and event == 'keyDown' else {})})
                    elif action == 'scroll':
                        delta = max(-600, min(600, float(data['delta'])))
                        await screen_command('Input.dispatchMouseEvent', {'type': 'mouseWheel',
                            'x': 350, 'y': 350, 'deltaX': 0, 'deltaY': delta})
                    else:
                        return JSONResponse({'error': 'unsupported action'}, status_code=400)
                    return {'ok': True}
                except Exception:
                    return JSONResponse({'error': 'browser command failed'}, status_code=503)

    novnc = os.environ.get('SHINWOL_NOVNC_PATH', '/usr/share/novnc')
    if os.path.isdir(novnc):
        app.mount('/novnc', StaticFiles(directory=novnc), name='novnc')
    return app
SHINWOL_GATEWAY_END
COPY --chmod=644 <<'SHINWOL_START_END' /app/start.py
"""Run Chrome, display, and authenticated gateway in a single container."""
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

children = []


def stop(*_):
    for child in reversed(children):
        if child.poll() is None:
            child.terminate()
    for child in children:
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
    raise SystemExit(0)


def start(argv):
    # Chromium and X11 diagnostics can include page URLs; suppress by default.
    child = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    children.append(child)
    return child


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
origin = os.environ.get('SHINWOL_PUBLIC_ORIGIN') or os.environ.get('RENDER_EXTERNAL_URL', '')
os.environ['SHINWOL_PUBLIC_ORIGIN'] = origin
token = os.environ.get('SHINWOL_CONTROL_TOKEN', '')
if not origin.startswith('https://') or len(token) < 32:
    sys.exit('Set HTTPS SHINWOL_PUBLIC_ORIGIN and a secret SHINWOL_CONTROL_TOKEN (32+ characters).')
profile = Path('/data/chrome')
profile.mkdir(mode=0o700, parents=True, exist_ok=True)
profile.chmod(0o700)
proxy_ca = os.environ.get('SHINWOL_PROXY_CA_FILE')
if proxy_ca:
    # Trust the managed environment's public proxy CA in Chromium's own NSS
    # database. Do not disable TLS verification or put CA material in the image.
    nss = Path.home() / '.pki' / 'nssdb'
    nss.mkdir(mode=0o700, parents=True, exist_ok=True)
    database = 'sql:' + str(nss)
    if not (nss / 'cert9.db').exists():
        subprocess.run(['certutil', '-N', '-d', database, '--empty-password'], check=True)
    subprocess.run(['certutil', '-A', '-d', database, '-n', 'managed-session-proxy',
                    '-t', 'C,,', '-i', proxy_ca], check=True)
os.environ['DISPLAY'] = ':99'
start(['Xvfb', ':99', '-screen', '0', '1280x900x24', '-nolisten', 'tcp'])
time.sleep(1)
chrome = ['chromium', '--no-sandbox', '--disable-dev-shm-usage', '--disable-crashpad-for-testing',
          '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=9222',
          '--user-data-dir=/data/chrome', '--no-first-run', '--no-default-browser-check',
          '--window-size=1280,900']
proxy = os.environ.get('HTTPS_PROXY') or os.environ.get('HTTP_PROXY')
if proxy:
    chrome.append('--proxy-server=' + proxy)
if os.environ.get('SHINWOL_NETWORK_IN_PROCESS') == '1':
    # Compatibility for hosts where the separate network process crashes.
    chrome.append('--enable-features=NetworkServiceInProcess2')
# Start on a stable local page. Network/login navigation happens only after the
# user opens the remote screen; a stalled startup navigation can stall CDP attach.
chrome.append('about:blank')
start(chrome)
start([sys.executable, '-m', 'uvicorn', 'gateway:create_app', '--factory', '--host', '0.0.0.0',
       '--port', os.environ.get('PORT', '8080'), '--no-access-log', '--log-level', 'warning'])
while True:
    for child in children:
        if child.poll() is not None:
            print('A browser service process exited; stopping the container.', file=sys.stderr)
            stop()
    time.sleep(1)
SHINWOL_START_END
# Keep the large installation in one layer (important on VFS Docker workers).
# noVNC is static browser code; its Debian proxy dependencies are unnecessary.
RUN --mount=type=secret,id=proxy_ca \
    set -eu; apt-get update; apt-get install -y --no-install-recommends \
    chromium xvfb x11vnc fonts-noto-cjk ca-certificates libnss3-tools; \
    cd /tmp; apt-get download novnc; dpkg-deb -x novnc_*.deb /tmp/novnc-assets; \
    cp -a /tmp/novnc-assets/usr/share/novnc /usr/share/novnc; \
    rm -rf /tmp/novnc-assets /tmp/novnc_*.deb /var/lib/apt/lists/*; \
    cd /app; useradd -m -u 1000 browser; mkdir /data; chown browser:browser /data; \
    if [ -f /run/secrets/proxy_ca ]; then export PIP_CERT=/run/secrets/proxy_ca; fi; \
    python -m pip install --no-cache-dir -r requirements.txt
USER browser
EXPOSE 8080
CMD ["python", "start.py"]
