#!/usr/bin/env python3
"""Graba lab/demo.sh y genera el GIF/MP4 del README. Herramienta de desarrollo.

    uv run --no-project --with pillow python lab/record_demo.py record docs/assets/arx-demo.cast
    uv run --no-project --with pillow python lab/record_demo.py render docs/assets/arx-demo.cast docs/assets/arx-demo.gif
    uv run --no-project --with pillow python lab/record_demo.py social docs/assets/social-preview.png

La salida es la real del script, con sus tiempos: solo se recortan las esperas largas
(MAX_GAP) y la preparación anterior a START. No se edita ni se reescribe ningún texto.
El MP4 se saca del GIF con ffmpeg.
"""
import json
import os
import pty
import re
import select
import subprocess
import sys
import time

START = "=== ARX DEMO START ==="
MAX_GAP = 2.5
COLS, ROWS = 104, 30
FONT = "/System/Library/Fonts/Menlo.ttc"
FG, BG = (214, 219, 224), (16, 20, 26)
SGR = {"31": (240, 98, 98), "32": (102, 204, 122), "33": (232, 190, 92), "36": (86, 196, 214)}


def record(out):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("bash", ["bash", "lab/demo.sh"])
    t0 = time.monotonic()
    events = []
    while True:
        ready, _, _ = select.select([fd], [], [], 1)
        if not ready:
            if os.waitpid(pid, os.WNOHANG)[0]:
                break
            continue
        try:
            data = os.read(fd, 65536)
        except OSError:
            break
        if not data:
            break
        sys.stdout.write(data.decode("utf-8", "replace"))
        sys.stdout.flush()
        events.append((time.monotonic() - t0, data.decode("utf-8", "replace")))
    text = "".join(e[1] for e in events)
    if START not in text:
        sys.exit("la demo no llegó a START: no se escribe la grabación")
    # solo lo posterior a START, con las esperas largas acotadas
    started, clock, last = False, 0.0, 0.0
    with open(out, "w", encoding="utf-8") as f:
        f.write(json.dumps({"version": 2, "width": COLS, "height": ROWS}) + "\n")
        for t, chunk in events:
            if not started:
                if START in chunk:
                    started, last = True, t
                    chunk = chunk.split(START, 1)[1]
                else:
                    continue
            clock += min(t - last, MAX_GAP)
            last = t
            f.write(json.dumps([round(clock, 3), "o", chunk], ensure_ascii=False) + "\n")
    print(f"\ngrabación: {out} ({clock:.0f} s)")


def _parse(text, color=FG, bold=False, dim=False):
    """Texto con SGR → lista de líneas, cada una lista de (carácter, color)."""
    lines, cur = [], []
    for part in re.split(r"(\x1b\[[0-9;]*m)", text.replace("\r", "")):
        m = re.fullmatch(r"\x1b\[([0-9;]*)m", part)
        if m:
            for code in (m.group(1) or "0").split(";"):
                if code == "0":
                    color, bold, dim = FG, False, False
                elif code == "1":
                    bold = True
                elif code == "2":
                    dim = True
                elif code in SGR:
                    color = SGR[code]
            continue
        for ch in part:
            if ch == "\n" or len(cur) >= COLS - 2:
                lines.append(cur)
                cur = []
                if ch == "\n":
                    continue
            shade = tuple(int(c * 0.6) for c in color) if dim else color
            cur.append((ch, shade, bold))
    lines.append(cur)
    return lines


def render(cast, out):
    from PIL import Image, ImageDraw, ImageFont
    font = ImageFont.truetype(FONT, 15, index=0)
    bold = ImageFont.truetype(FONT, 15, index=1)
    cw, ch = font.getbbox("M")[2], 20
    w, h = COLS * cw + 32, ROWS * ch + 32
    events = [json.loads(line) for line in open(cast, encoding="utf-8")][1:]

    def frame(text):
        img = Image.new("RGB", (w, h), BG)
        d = ImageDraw.Draw(img)
        for y, line in enumerate(_parse(text)[-ROWS:]):
            for x, (c, color, is_bold) in enumerate(line):
                d.text((16 + x * cw, 16 + y * ch), c, font=bold if is_bold else font, fill=color)
        return img

    frames, durations, text = [], [], ""
    for i, (t, _, chunk) in enumerate(events):
        text += chunk
        next_t = events[i + 1][0] if i + 1 < len(events) else t + 6
        frames.append(frame(text.lstrip("\r\n")))
        durations.append(max(60, int((next_t - t) * 1000)))
    frames = [f.convert("P", palette=Image.ADAPTIVE, colors=48) for f in frames]
    frames[0].save(out, save_all=True, append_images=frames[1:], duration=durations, loop=0,
                   optimize=True, disposal=1)
    print(f"{out}: {len(frames)} fotogramas · {sum(durations) / 1000:.0f} s · "
          f"{os.path.getsize(out) / 1e6:.1f} MB")
    mp4 = out.rsplit(".", 1)[0] + ".mp4"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", out, "-movflags", "faststart",
                    "-pix_fmt", "yuv420p", "-vf", "pad=ceil(iw/2)*2:ceil(ih/2)*2", mp4], check=True)
    print(f"{mp4}: {os.path.getsize(mp4) / 1e6:.1f} MB")


def social(out):
    """Imagen 1280×640 para Settings → Social preview. Cada fila la demuestra lab/demo.sh."""
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new("RGB", (1280, 640), BG)
    d = ImageDraw.Draw(img)
    big = ImageFont.truetype(FONT, 104, index=1)
    mid = ImageFont.truetype(FONT, 31, index=0)
    row = ImageFont.truetype(FONT, 27, index=0)
    d.text((80, 66), "Arx", font=big, fill=SGR["36"])
    d.text((80, 204), "Autonomous defensive security for Linux servers", font=mid, fill=FG)
    rows = [("port scan", "source IP blocked"),
            ("SSH brute force", "source IP blocked"),
            ("reverse shell", "channel cut, shell suspended"),
            ("dropper in /tmp", "process suspended")]
    for i, (attack, answer) in enumerate(rows):
        y = 300 + i * 50
        d.text((80, y), attack, font=row, fill=SGR["31"])
        d.text((400, y), answer, font=row, fill=SGR["32"])
    d.text((80, 528), "Every automatic action undoes itself.", font=mid, fill=SGR["33"])
    img.save(out, optimize=True)
    print(f"{out}: {os.path.getsize(out) / 1e3:.0f} KB")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "record":
        record(sys.argv[2])
    elif cmd == "render":
        render(sys.argv[2], sys.argv[3])
    elif cmd == "social":
        social(sys.argv[2])
    else:
        sys.exit(__doc__)
