"""Regression tests for the issue #5637 streaming stale-anchor guards.

Once the reader is up in history during a live stream, the anchor captured for a
same-frame restore goes stale as the streaming chunk grows content ABOVE the viewport:
the anchor's captured topOffset (and the absolute snapshot.top) no longer map to the
same content, so realigning to them yanks a still reader backward by a few hundred px.
The existing `snapshot.userUnpinned===true` fallback skip is defeated because the
scrollHeight-collapse scroll event re-pins the state machine (flips userUnpinned back to
false) mid-stream.

Two guards close this, both keyed on content-growth-since-capture + absence of real
input intent (NOT a scrollTop diff, which the browser's own overflow-anchor writes on an
overflow-anchor:auto container):
  1. `_restoreMessageViewportAnchor` refuses the realign write.
  2. the absolute `snapshot.top` fallback in `_restoreMessageScrollSnapshotSameFrame`
     refuses its write.

Every behavioral test below is designed to FAIL on the pre-guard code and PASS only with
the guard. Node-harness pattern (extractFunc + mock DOM) shared with the sibling scroll
regression suites.
"""
import json
import pathlib
import shutil
import subprocess
import tempfile

import pytest

ROOT = pathlib.Path(__file__).parent.parent
UI_JS_PATH = ROOT / "static" / "ui.js"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node not on PATH")


def _run_node(source: str) -> str:
    with tempfile.NamedTemporaryFile(
        "w", suffix=".cjs", encoding="utf-8", dir=ROOT, delete=False
    ) as script:
        script.write(source)
        script_path = pathlib.Path(script.name)
    try:
        result = subprocess.run(
            [NODE, str(script_path)], cwd=str(ROOT),
            capture_output=True, text=True, timeout=30,
        )
    finally:
        script_path.unlink(missing_ok=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    return result.stdout.strip()


def _extract_func_script(js: str) -> str:
    prelude = "const src = " + json.dumps(js) + ";\n"
    body = r"""
function extractFunc(name) {
  const re = new RegExp('function\\s+' + name + '\\s*\\(');
  const start = src.search(re);
  if (start < 0) throw new Error(name + ' not found');
  let i = src.indexOf('{', start);
  let depth = 1; i++;
  let str = null, inLine = false, inBlock = false, inRegex = false, prev = '';
  while (depth > 0 && i < src.length) {
    const c = src[i], n = src[i + 1];
    if (inLine) { if (c === '\n') inLine = false; i++; continue; }
    if (inBlock) { if (c === '*' && n === '/') { inBlock = false; i++; } i++; continue; }
    if (str) { if (c === '\\') { i += 2; continue; } if (c === str) str = null; i++; continue; }
    if (inRegex) { if (c === '\\') { i += 2; continue; } if (c === '/') inRegex = false; i++; continue; }
    if (c === '/' && n === '/') { inLine = true; i += 2; continue; }
    if (c === '/' && n === '*') { inBlock = true; i += 2; continue; }
    if (c === '"' || c === "'" || c === '`') { str = c; i++; continue; }
    if (c === '/' && !'})]0123456789'.includes(prev) && !/[A-Za-z_$]/.test(prev)) { inRegex = true; i++; continue; }
    if (c === '{') depth++; else if (c === '}') depth--;
    if (c.trim()) prev = c;
    i++;
  }
  return src.slice(start, i);
}"""
    return prelude + body


# ---- realign guard (_restoreMessageViewportAnchor) -------------------------------

def _realign_harness(*, anchor_extra: str, cur_scroll_height: int, rect_top: int,
                     top_offset: int, active_intent: bool = False,
                     touch_like: bool = True) -> str:
    js = UI_JS_PATH.read_text(encoding="utf-8")
    intent_js = "true" if active_intent else "false"
    touch_js = "true" if touch_like else "false"
    return _extract_func_script(js) + f"""
let writes = [];
let stTop = 90030;
const row = {{ getBoundingClientRect(){{ return {{ top: {rect_top} }}; }},
  getClientRects(){{ return [{{}}]; }}, dataset: {{ messageAnchorKey: 'k1' }} }};
const container = {{
  get scrollTop(){{ return stTop; }}, set scrollTop(v){{ writes.push(Math.round(v)); stTop = v; }},
  scrollHeight: {cur_scroll_height}, clientHeight: 427,
  getBoundingClientRect(){{ return {{ top: 0, bottom: 427 }}; }},
  querySelectorAll(){{ return [row]; }}, querySelector(){{ return row; }}, style: {{}},
}};
function $(id){{ return id === 'messages' ? container : null; }}
function _recentMessageScrollIntent(){{ return {intent_js}; }}
function _recentMessageTouchScrollIntent(){{ return {intent_js}; }}
function _isTouchLikeMessageViewport(){{ return {touch_js}; }}
let _programmaticScroll = false; let _programmaticScrollSetAt = 0;
const performance = {{ now(){{ return 1; }} }};
function _suppressBrowserOverflowAnchor(){{ return null; }}
function _deferClearProgrammaticScroll(){{}}
function requestAnimationFrame(cb){{ cb(); }}
function setTimeout(cb){{ cb(); return 1; }}
const anchor = Object.assign({{ rawIdx: 53, sessionIdx: 53, key: 'k1', topOffset: {top_offset} }}, {anchor_extra});
eval(extractFunc('_restoreMessageViewportAnchor'));
const returned = _restoreMessageViewportAnchor(anchor, 0);
console.log(JSON.stringify({{ returned, wrote: writes.length }}));
"""


def test_realign_refuses_stale_anchor_when_content_grew_no_intent():
    """Content grew since capture (90000->90453) and no input intent, realign delta -453
    -> REFUSE (return false, no write). Mutation: delete the guard block and it writes."""
    m = json.loads(_run_node(_realign_harness(
        anchor_extra="{scrollHeightAtCapture: 90000}",
        cur_scroll_height=90453, rect_top=-453, top_offset=0, active_intent=False,
    )))
    assert m["returned"] is False and m["wrote"] == 0


def test_realign_allows_fresh_anchor_no_growth():
    """No growth since capture -> realign runs normally even with the same delta."""
    m = json.loads(_run_node(_realign_harness(
        anchor_extra="{scrollHeightAtCapture: 90453}",
        cur_scroll_height=90453, rect_top=-453, top_offset=0, active_intent=False,
    )))
    assert m["returned"] is True and m["wrote"] == 1


def test_realign_allows_with_active_intent():
    """Recent real input intent -> keep the legitimate realign even if content grew."""
    m = json.loads(_run_node(_realign_harness(
        anchor_extra="{scrollHeightAtCapture: 90000}",
        cur_scroll_height=90453, rect_top=-453, top_offset=0, active_intent=True,
    )))
    assert m["returned"] is True and m["wrote"] == 1


def test_realign_backward_compatible_without_capture_geometry():
    """Legacy anchor without scrollHeightAtCapture -> guard is a no-op, prior behavior."""
    m = json.loads(_run_node(_realign_harness(
        anchor_extra="{}",
        cur_scroll_height=90453, rect_top=-453, top_offset=0, active_intent=False,
    )))
    assert m["returned"] is True and m["wrote"] == 1


def test_realign_allows_on_desktop_no_native_anchor():
    """Desktop regression (#5637 gate cert): the exact stale-anchor case
    (content grew, no intent, delta -453) but on a hover+fine-pointer viewport where
    `.messages` is `overflow-anchor:none`. There is no native anchoring layer to hold
    the reader, so the guard MUST NOT refuse — the semantic scrollTop realign has to
    run or the desktop reader is left unheld after above-viewport growth.
    Mutation: drop the `_touchHold&&` term from the realign guard and this FAILS
    (the write is wrongly refused on desktop)."""
    m = json.loads(_run_node(_realign_harness(
        anchor_extra="{scrollHeightAtCapture: 90000}",
        cur_scroll_height=90453, rect_top=-453, top_offset=0, active_intent=False,
        touch_like=False,
    )))
    assert m["returned"] is True and m["wrote"] == 1


# ---- fallback guard (_restoreMessageScrollSnapshotSameFrame) ---------------------

def _fallback_harness(*, snapshot_scroll_height, cur_scroll_height, snapshot_top,
                      active_intent: bool = False, touch_like: bool = True) -> str:
    js = UI_JS_PATH.read_text(encoding="utf-8")
    intent_js = "true" if active_intent else "false"
    touch_js = "true" if touch_like else "false"
    sh = "null" if snapshot_scroll_height is None else str(snapshot_scroll_height)
    return _extract_func_script(js) + f"""
let writes = [];
let stTop = 90030;
const el = {{
  get scrollTop(){{ return stTop; }}, set scrollTop(v){{ writes.push(Math.round(v)); stTop = v; }},
  scrollHeight: {cur_scroll_height}, clientHeight: 427,
}};
function $(id){{ return id === 'messages' ? el : null; }}
function _recentMessageScrollIntent(){{ return {intent_js}; }}
function _recentMessageTouchScrollIntent(){{ return {intent_js}; }}
function _isTouchLikeMessageViewport(){{ return {touch_js}; }}
// realign path fails (no anchor) so execution reaches the absolute fallback
function _restorePinnedMessageScrollSnapshot(){{ return false; }}
function _restoreMessageViewportAnchor(){{ return false; }}
function _remountMessageViewportAnchor(){{ return false; }}
let _messageUserUnpinned = false; let _scrollPinned = true; let _nearBottomCount = 5;
let _lastScrollTop = 0; let _lastMessageClientHeight = 0;
let _programmaticScroll = false; let _programmaticScrollSetAt = 0;
const performance = {{ now(){{ return 1; }} }};
function _deferClearProgrammaticScroll(){{}}
function requestAnimationFrame(cb){{ cb(); }}
function setTimeout(cb){{ cb(); return 1; }}
const snapshot = {{ anchor: null, top: {snapshot_top}, bottom: 40,
  scrollHeight: {sh}, pinned: false, userUnpinned: false }};
eval(extractFunc('_restoreMessageScrollSnapshotSameFrame'));
_restoreMessageScrollSnapshotSameFrame(snapshot);
console.log(JSON.stringify({{ wrote: writes.length, writes,
  messageUserUnpinned: _messageUserUnpinned, scrollPinned: _scrollPinned }}));
"""


def test_fallback_refuses_stale_snapshot_top_when_content_grew_no_intent():
    """Content grew since snapshot (90000->90453), reader not pinned, no intent, and the
    absolute snapshot.top write would move scrollTop >8px -> REFUSE. This is the -578
    on-device jump the userUnpinned check missed (re-pin flipped userUnpinned false).
    Mutation: delete the fallback guard block and scrollHistory gets the stale write."""
    m = json.loads(_run_node(_fallback_harness(
        snapshot_scroll_height=90000, cur_scroll_height=90453, snapshot_top=89577,
        active_intent=False,
    )))
    assert m["writes"] == []
    assert m["messageUserUnpinned"] is True and m["scrollPinned"] is False


def test_fallback_allows_snapshot_top_when_no_growth():
    """No growth since snapshot -> the fallback keeps its authoritative absolute restore."""
    m = json.loads(_run_node(_fallback_harness(
        snapshot_scroll_height=90453, cur_scroll_height=90453, snapshot_top=89577,
        active_intent=False,
    )))
    assert m["writes"] == [89577]


def test_fallback_backward_compatible_without_capture_scrollheight():
    """Legacy snapshot without scrollHeight -> guard no-op, prior absolute restore runs."""
    m = json.loads(_run_node(_fallback_harness(
        snapshot_scroll_height=None, cur_scroll_height=90453, snapshot_top=89577,
        active_intent=False,
    )))
    assert m["writes"] == [89577]


def test_fallback_allows_snapshot_top_with_active_intent():
    """Content grew since snapshot, but the reader has recent real input intent -> the
    fallback keeps its legitimate absolute restore (an actively-scrolling reader owns the
    snapshot). Mirrors the realign-guard active-intent case.
    Mutation: drop the `!_activeIntent` term from the fallback guard and this fails
    (the write would be wrongly refused)."""
    m = json.loads(_run_node(_fallback_harness(
        snapshot_scroll_height=90000, cur_scroll_height=90453, snapshot_top=89577,
        active_intent=True,
    )))
    assert m["writes"] == [89577]


def test_fallback_allows_snapshot_top_on_desktop_no_native_anchor():
    """Desktop regression (#5637 gate cert): the exact stale-snapshot case (content grew,
    reader not pinned, no intent, absolute write would move >8px) but on a
    hover+fine-pointer viewport where `.messages` is `overflow-anchor:none`. With no
    native anchoring layer to hold the reader, the fallback MUST keep its absolute
    snapshot.top restore rather than refuse and latch userUnpinned — otherwise the
    desktop reader is left at the wrong absolute position and force-unpinned.
    Mutation: drop the `_fbTouchHold&&` term from the fallback guard and this FAILS
    (the write is wrongly refused and userUnpinned is latched on desktop)."""
    m = json.loads(_run_node(_fallback_harness(
        snapshot_scroll_height=90000, cur_scroll_height=90453, snapshot_top=89577,
        active_intent=False, touch_like=False,
    )))
    assert m["writes"] == [89577]
    assert m["messageUserUnpinned"] is False and m["scrollPinned"] is True

