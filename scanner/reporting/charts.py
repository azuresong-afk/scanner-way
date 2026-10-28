"""Диаграммы отчёта: одна геометрия -> inline-SVG (HTML/PDF) и PNG (DOCX).

Каждая диаграмма строится как `Scene` — список примитивов (прямоугольник,
линия, текст, сектор кольца) в пиксельных координатах. Из сцены получаются:
  * SVG без внешних ресурсов и JS — одинаково рендерится браузером и
    WeasyPrint; подсказки при наведении — нативные `<title>`;
  * PNG через Pillow (тянется зависимостью WeasyPrint) — для вставки в DOCX.

Строки (хосты, названия модулей) приходят из недоверенных данных находок —
в SVG они экранируются.
"""
from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import cache
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape

from scanner.core.models import FindingStatus, Severity
from scanner.reporting.model import SEVERITY_LABELS, SEVERITY_ORDER

FONT = "Inter, DejaVu Sans"

# Цвета критичности (как у Nessus/Qualys: тёмно-красный -> оранжевый -> янтарный
# -> синий -> серый). «Информационный» намеренно нейтрально-серый. Цвет никогда не
# единственный носитель смысла: у диаграмм всегда есть легенда/подписи и таблица.
SEVERITY_HEX: dict[Severity, str] = {
    Severity.CRITICAL: "#b42318",
    Severity.HIGH: "#e8590c",
    Severity.MEDIUM: "#d29a0b",
    Severity.LOW: "#2f6fb3",
    Severity.INFO: "#a0a8b5",
}
STATUS_HEX: dict[FindingStatus, str] = {
    FindingStatus.NEW: "#e8590c",
    FindingStatus.REGRESSION: "#b42318",
    FindingStatus.OPEN: "#5b6475",
    FindingStatus.FIXED: "#067647",
}
INK, MUTED, GRID, SURFACE = "#101828", "#667085", "#f2f4f7", "#ffffff"
NEUTRAL, ACCENT, AXIS = "#d0d5dd", "#1d2b4f", "#d0d5dd"


# --- примитивы ------------------------------------------------------------------

@dataclass(slots=True)
class Rect:
    x: float
    y: float
    w: float
    h: float
    fill: str
    round_end: str | None = None   # "right" | "top" — скруглённый конец данных
    title: str | None = None


@dataclass(slots=True)
class Line:
    x1: float
    y1: float
    x2: float
    y2: float
    stroke: str = GRID
    width: float = 1


@dataclass(slots=True)
class Text:
    x: float
    y: float                       # базовая линия
    text: str
    size: float = 11
    fill: str = INK
    anchor: str = "start"          # start | middle | end
    bold: bool = False


@dataclass(slots=True)
class Arc:
    """Сектор кольца; углы в градусах по часовой от 12 часов."""
    cx: float
    cy: float
    r: float
    r_inner: float
    a0: float
    a1: float
    fill: str
    title: str | None = None


@dataclass(slots=True)
class Scene:
    key: str
    width: int
    height: int
    label: str                     # aria-label: что изображено
    shapes: list = field(default_factory=list)

    def add(self, *shapes) -> None:
        self.shapes.extend(shapes)

    # --- SVG ---------------------------------------------------------------------
    def to_svg(self) -> str:
        out = [(f'<svg xmlns="http://www.w3.org/2000/svg" class="chart" '
                f'data-chart="{self.key}" viewBox="0 0 {self.width} {self.height}" '
                f'width="{self.width}" height="{self.height}" role="img" '
                f'aria-label="{_attr(self.label)}" '
                f'font-family="{FONT}, Arial, sans-serif">')]
        out.extend(_svg_shape(s) for s in self.shapes)
        out.append("</svg>")
        return "".join(out)

    # --- PNG ---------------------------------------------------------------------
    def to_png(self, scale: int = 3) -> bytes:
        from PIL import Image, ImageDraw

        img = Image.new("RGB", (self.width * scale, self.height * scale), SURFACE)
        d = ImageDraw.Draw(img)
        k = scale
        texts = []
        for s in self.shapes:
            if isinstance(s, Rect):
                _png_rect(d, s, k)
            elif isinstance(s, Line):
                d.line([(s.x1 * k, s.y1 * k), (s.x2 * k, s.y2 * k)],
                       fill=s.stroke, width=max(1, round(s.width * k)))
            elif isinstance(s, Arc):
                box = [(s.cx - s.r) * k, (s.cy - s.r) * k, (s.cx + s.r) * k, (s.cy + s.r) * k]
                # Pillow: 0° — 3 часа, по часовой; у нас 0° — 12 часов
                d.pieslice(box, s.a0 - 90, s.a1 - 90, fill=s.fill,
                           outline=SURFACE, width=2 * k)
            elif isinstance(s, Text):
                texts.append(s)
        # «дырка» кольца — после всех секторов; текст — поверх всего
        for s in self.shapes:
            if isinstance(s, Arc):
                ri = s.r_inner * k
                d.ellipse([s.cx * k - ri, s.cy * k - ri, s.cx * k + ri, s.cy * k + ri],
                          fill=SURFACE)
        for s in texts:
            anchor = {"start": "ls", "middle": "ms", "end": "rs"}[s.anchor]
            d.text((s.x * k, s.y * k), s.text, fill=s.fill,
                   font=_font(round(s.size * k), s.bold), anchor=anchor)
        buf = BytesIO()
        img.save(buf, format="PNG", optimize=True)
        return buf.getvalue()


def _attr(v: str) -> str:
    return escape(v, {'"': "&quot;"})


def _svg_title(t: str | None) -> str:
    return f"<title>{escape(t)}</title>" if t else ""


def _svg_shape(s) -> str:
    if isinstance(s, Rect):
        if s.w <= 0 or s.h <= 0:
            return ""
        r = min(4.0, s.w / 2, s.h / 2) if s.round_end else 0
        if s.round_end == "right":
            x, y, w, h = s.x, s.y, s.w, s.h
            d = (f"M{x:.1f},{y:.1f}H{x + w - r:.1f}Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f}"
                 f"V{y + h - r:.1f}Q{x + w:.1f},{y + h:.1f} {x + w - r:.1f},{y + h:.1f}"
                 f"H{x:.1f}Z")
        elif s.round_end == "top":
            x, y, w, h = s.x, s.y, s.w, s.h
            d = (f"M{x:.1f},{y + h:.1f}V{y + r:.1f}Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f}"
                 f"H{x + w - r:.1f}Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f}"
                 f"V{y + h:.1f}Z")
        else:
            return (f'<rect x="{s.x:.1f}" y="{s.y:.1f}" width="{s.w:.1f}" '
                    f'height="{s.h:.1f}" fill="{s.fill}">{_svg_title(s.title)}</rect>')
        return f'<path d="{d}" fill="{s.fill}">{_svg_title(s.title)}</path>'
    if isinstance(s, Line):
        return (f'<line x1="{s.x1:.1f}" y1="{s.y1:.1f}" x2="{s.x2:.1f}" y2="{s.y2:.1f}" '
                f'stroke="{s.stroke}" stroke-width="{s.width}"/>')
    if isinstance(s, Text):
        weight = ' font-weight="bold"' if s.bold else ""
        return (f'<text x="{s.x:.1f}" y="{s.y:.1f}" font-size="{s.size}" fill="{s.fill}" '
                f'text-anchor="{s.anchor}"{weight}>{escape(s.text)}</text>')
    if isinstance(s, Arc):
        return (f'<path d="{_arc_path(s)}" fill="{s.fill}" stroke="{SURFACE}" '
                f'stroke-width="2">{_svg_title(s.title)}</path>')
    raise TypeError(s)


def _pt(cx: float, cy: float, r: float, a: float) -> tuple[float, float]:
    rad = math.radians(a)
    return cx + r * math.sin(rad), cy - r * math.cos(rad)


def _arc_path(s: Arc) -> str:
    a1 = s.a1 if s.a1 - s.a0 < 360 else s.a0 + 359.99
    large = 1 if a1 - s.a0 > 180 else 0
    x0, y0 = _pt(s.cx, s.cy, s.r, s.a0)
    x1, y1 = _pt(s.cx, s.cy, s.r, a1)
    x2, y2 = _pt(s.cx, s.cy, s.r_inner, a1)
    x3, y3 = _pt(s.cx, s.cy, s.r_inner, s.a0)
    return (f"M{x0:.2f},{y0:.2f}A{s.r},{s.r} 0 {large} 1 {x1:.2f},{y1:.2f}"
            f"L{x2:.2f},{y2:.2f}A{s.r_inner},{s.r_inner} 0 {large} 0 {x3:.2f},{y3:.2f}Z")


def _png_rect(d, s: Rect, k: int) -> None:
    if s.w <= 0 or s.h <= 0:
        return
    x0, y0, x1, y1 = s.x * k, s.y * k, (s.x + s.w) * k, (s.y + s.h) * k
    r = min(4.0, s.w / 2, s.h / 2) * k if s.round_end else 0
    if not r:
        d.rectangle([x0, y0, x1, y1], fill=s.fill)
        return
    d.rounded_rectangle([x0, y0, x1, y1], radius=r, fill=s.fill)
    # конец у базовой линии — прямой
    if s.round_end == "right":
        d.rectangle([x0, y0, x0 + r, y1], fill=s.fill)
    else:
        d.rectangle([x0, y1 - r, x1, y1], fill=s.fill)


_FONT_DIRS = ("/usr/share/fonts", "/usr/local/share/fonts", "/Library/Fonts",
              "C:/Windows/Fonts")


@cache
def _font_path(bold: bool) -> str | None:
    name = "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"
    for root in _FONT_DIRS:
        p = Path(root)
        if p.is_dir():
            for hit in p.rglob(name):
                return str(hit)
    return None


@cache
def _font(size: int, bold: bool):
    from PIL import ImageFont

    path = _font_path(bold) or _font_path(False)
    if path:
        return ImageFont.truetype(path, size)
    return ImageFont.load_default(size)  # без кириллицы; DejaVu есть в Docker-образе


def png_available() -> bool:
    try:
        import PIL  # noqa: F401
    except ImportError:
        return False
    return True


# --- вспомогательное -----------------------------------------------------------------

def _scale(v: int) -> tuple[int, int]:
    """Шкала оси: (верх, шаг) — «круглый» шаг, не больше 5 делений."""
    v = max(v, 1)
    mag = 1
    while True:
        for m in (1, 2, 5):
            step = m * mag
            if v / step <= 5:
                return -(-v // step) * step, step
        mag *= 10


def _ticks(top: int, step: int) -> list[int]:
    return list(range(0, top + 1, step))


def _short(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _pct(part: int, total: int) -> str:
    return f"{round(100 * part / total)}%" if total else "0%"


def _legend(scene: Scene, x: float, y: float, items: Sequence[tuple[str, str]],
            gap: float = 12) -> float:
    """Легенда с переносом строк; возвращает базовую линию последней строки."""
    x0 = x
    for label, color in items:
        w = 14 + len(label) * 6.0
        if x > x0 and x + w > scene.width:
            x, y = x0, y + 15
        scene.add(Rect(x, y - 9, 10, 10, color), Text(x + 14, y, label, 10, MUTED))
        x += w + gap
    return y


# --- диаграммы ----------------------------------------------------------------------

def severity_donut(counts: dict[Severity, int]) -> Scene:
    """Кольцо распределения по уровню опасности + легенда с числом и долей."""
    total = sum(counts.values())
    sc = Scene("severity", 340, 180, "Распределение находок по уровню опасности")
    cx, cy, r, ri = 88, 90, 76, 56
    if total:
        a = 0.0
        for s in SEVERITY_ORDER:
            n = counts[s]
            if not n:
                continue
            span = 360 * n / total
            sc.add(Arc(cx, cy, r, ri, a, a + span, SEVERITY_HEX[s],
                       f"{SEVERITY_LABELS[s]}: {n} ({_pct(n, total)})"))
            a += span
    else:
        sc.add(Arc(cx, cy, r, ri, 0, 360, GRID, "Находок нет"))
    sc.add(Text(cx, cy + 5, str(total), 26, INK, "middle", bold=True),
           Text(cx, cy + 22, "находок", 9, MUTED, "middle"))
    y = 38
    for s in SEVERITY_ORDER:
        n = counts[s]
        sc.add(Rect(186, y - 10, 11, 11, SEVERITY_HEX[s]),
               Text(203, y, SEVERITY_LABELS[s], 10.5, INK),
               Text(316, y, str(n), 10.5, INK, "end", bold=True),
               Text(338, y, _pct(n, total), 9, MUTED, "end"))
        y += 27
    return sc


def stacked_bars(key: str, label: str, rows: Sequence[tuple[str, dict[Severity, int]]],
                 width: int = 520, label_w: int = 150) -> Scene:
    """Горизонтальные столбцы с разбивкой по опасности (хосты, модули)."""
    band, bar, bottom = 26, 13, 22
    sc = Scene(key, width, 0, label)
    top_pad = _legend(sc, 4, 12, [(SEVERITY_LABELS[s], SEVERITY_HEX[s])
                                  for s in SEVERITY_ORDER]) + 14
    base_y = top_pad + band * max(len(rows), 1)
    sc.height = round(base_y + bottom)
    plot_w = width - label_w - 34
    max_chars = max(6, int((label_w - 10) / 6.4))
    peak, step = _scale(max((sum(c.values()) for _, c in rows), default=0))
    for t in _ticks(peak, step):
        x = label_w + plot_w * t / peak
        sc.add(Line(x, top_pad - 4, x, base_y),
               Text(x, base_y + 14, str(t), 9, MUTED, "middle"))
    for i, (name, counts) in enumerate(rows):
        y = top_pad + i * band + (band - bar) / 2
        total = sum(counts.values())
        sc.add(Text(label_w - 8, y + bar / 2 + 4, _short(name, max_chars), 10.5, INK, "end"))
        x = label_w
        segs = [s for s in SEVERITY_ORDER if counts.get(s)]
        for j, s in enumerate(segs):
            w = plot_w * counts[s] / peak
            last = j == len(segs) - 1
            sc.add(Rect(x, y, max(w - (0 if last else 2), 0.5), bar, SEVERITY_HEX[s],
                        "right" if last else None,
                        f"{name} — {SEVERITY_LABELS[s]}: {counts[s]}"))
            x += w
        sc.add(Text(x + 5, y + bar / 2 + 4, str(total), 10, INK, bold=True))
    if not rows:
        sc.add(Text(width / 2, top_pad + band / 2 + 4, "Нет данных", 10.5, MUTED, "middle"))
    return sc


@dataclass(slots=True)
class RunPoint:
    """Точка истории прогонов для графика тренда."""
    label: str
    counts: dict[Severity, int]


def trend_columns(points: Sequence[RunPoint], width: int = 340) -> Scene:
    """Столбцы по прогонам: состав находок по опасности, итог над столбцом."""
    sc = Scene("trend", width, 0, "Динамика числа находок по прогонам")
    top = _legend(sc, 4, 12, [(SEVERITY_LABELS[s], SEVERITY_HEX[s])
                              for s in SEVERITY_ORDER]) + 24
    base = top + 150
    sc.height = round(base + 26)
    left = 34
    plot_w, plot_h = width - left - 8, base - top
    peak, step = _scale(max((sum(p.counts.values()) for p in points), default=0))
    for t in _ticks(peak, step):
        y = base - plot_h * t / peak
        sc.add(Line(left, y, width - 8, y), Text(left - 6, y + 3, str(t), 9, MUTED, "end"))
    n = max(len(points), 1)
    slot = plot_w / n
    col = min(30, slot * 0.5)
    for i, p in enumerate(points):
        x = left + slot * i + (slot - col) / 2
        y = base
        segs = [s for s in reversed(SEVERITY_ORDER) if p.counts.get(s)]
        for j, s in enumerate(segs):
            h = plot_h * p.counts[s] / peak
            last = j == len(segs) - 1
            sc.add(Rect(x, y - h + (0 if last else 2), col, max(h - (0 if last else 2), 0.5),
                        SEVERITY_HEX[s], "top" if last else None,
                        f"{p.label} — {SEVERITY_LABELS[s]}: {p.counts[s]}"))
            y -= h
        total = sum(p.counts.values())
        sc.add(Text(x + col / 2, y - 5, str(total), 10, INK, "middle", bold=True),
               Text(x + col / 2, base + 15, _short(p.label, 14), 9.5, MUTED, "middle"))
    sc.add(Line(left, base, width - 8, base, AXIS))
    return sc


def waterfall(previous: int, fixed: int, new: int, regression: int,
              width: int = 340) -> Scene:
    """Каскад: было -> устранено -> новые -> повторно -> стало."""
    height = 210
    sc = Scene("waterfall", width, height, "Изменение числа находок с предыдущего прогона")
    current = previous - fixed + new + regression
    steps = [
        ("Было", 0, previous, NEUTRAL, f"Предыдущий прогон: {previous}"),
        ("Устранено", previous - fixed, previous, STATUS_HEX[FindingStatus.FIXED],
         f"Устранено: −{fixed}"),
        ("Новые", previous - fixed, previous - fixed + new, STATUS_HEX[FindingStatus.NEW],
         f"Новые: +{new}"),
        ("Повторно", previous - fixed + new, current, STATUS_HEX[FindingStatus.REGRESSION],
         f"Повторно выявлены: +{regression}"),
        ("Стало", 0, current, ACCENT, f"Текущий прогон: {current}"),
    ]
    left, top, base = 34, 24, height - 26
    plot_w, plot_h = width - left - 8, base - top
    peak, step = _scale(max(previous, current, previous - fixed + new))
    for t in _ticks(peak, step):
        y = base - plot_h * t / peak
        sc.add(Line(left, y, width - 8, y), Text(left - 6, y + 3, str(t), 9, MUTED, "end"))
    slot = plot_w / len(steps)
    col = min(32, slot * 0.55)
    values = [previous, -fixed, new, regression, current]
    for i, (name, lo, hi, color, title) in enumerate(steps):
        x = left + slot * i + (slot - col) / 2
        y_hi, y_lo = base - plot_h * hi / peak, base - plot_h * lo / peak
        sc.add(Rect(x, y_hi, col, max(y_lo - y_hi, 0.5 if hi == lo else 0), color,
                    "top" if lo == 0 else None, title))
        v = values[i]
        txt = str(v) if i in (0, 4) else (f"{v:+d}" if v else "0").replace("-", "−")
        sc.add(Text(x + col / 2, y_hi - 5, txt, 10, INK, "middle", bold=True),
               Text(x + col / 2, base + 15, name, 9.5, MUTED, "middle"))
        if 0 < i < len(steps) - 1:   # соединитель уровня с предыдущим шагом
            level = hi if i == 1 else lo
            yl = base - plot_h * level / peak
            sc.add(Line(x - (slot - col), yl, x, yl, AXIS, 1))
    sc.add(Line(left, base, width - 8, base, AXIS))
    return sc
