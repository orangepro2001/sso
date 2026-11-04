#!/usr/bin/env python3
"""Dump every structural detail of the reference workbook (docs/source-rev02.xlsx).

The output is the machine-readable basis for docs/excel-schema.md, which in turn is
the contract the PhpSpreadsheet exporter must satisfy cell for cell.

    python3 tools/inspect_xlsx.py [path]

Prints JSON to stdout: sheets, dimensions, merged ranges, column widths, row
heights, per-cell style ids plus the resolved style table, data validations,
conditional formatting, print setup and defined names.
"""
import json
import sys
from collections import OrderedDict

from openpyxl import load_workbook
from openpyxl.utils import get_column_letter

PATH = sys.argv[1] if len(sys.argv) > 1 else "docs/source-rev02.xlsx"

wb = load_workbook(PATH, data_only=False)
wbv = load_workbook(PATH, data_only=True)


def color_repr(c):
    if c is None:
        return None
    if c.type == "rgb":
        return c.rgb
    if c.type == "theme":
        return "theme:%s:tint:%s" % (c.theme, round(c.tint, 4))
    if c.type == "indexed":
        return "indexed:%s" % c.indexed
    return str(c.value)


def font_repr(f):
    return OrderedDict(
        name=f.name,
        size=f.sz,
        bold=f.b,
        italic=f.i,
        underline=f.u,
        strike=f.strike,
        color=color_repr(f.color),
    )


def fill_repr(f):
    if f is None or f.fill_type is None:
        return None
    return OrderedDict(type=f.fill_type, fg=color_repr(f.fgColor), bg=color_repr(f.bgColor))


def border_repr(b):
    if b is None:
        return None
    out = {}
    for side in ("left", "right", "top", "bottom"):
        s = getattr(b, side)
        if s is not None and s.style:
            out[side] = OrderedDict(style=s.style, color=color_repr(s.color))
    return out or None


def align_repr(a):
    if a is None:
        return None
    out = OrderedDict(
        h=a.horizontal, v=a.vertical, wrap=a.wrap_text, indent=a.indent, rot=a.textRotation
    )
    return {k: v for k, v in out.items() if v is not None} or None


def cell_repr(c, value):
    d = OrderedDict()
    d["ref"] = c.coordinate
    d["v"] = value
    if c.data_type and c.data_type != "n":
        d["t"] = c.data_type
    if c.number_format and c.number_format != "General":
        d["fmt"] = c.number_format
    if c.font and (
        c.font.name != "Calibri"
        or c.font.sz not in (None, 11)
        or c.font.b
        or c.font.i
        or c.font.u
        or (c.font.color is not None and color_repr(c.font.color) not in (None, "FF000000"))
    ):
        d["font"] = font_repr(c.font)
    f = fill_repr(c.fill)
    if f:
        d["fill"] = f
    b = border_repr(c.border)
    if b:
        d["border"] = b
    a = align_repr(c.alignment)
    if a:
        d["align"] = a
    return d


report = OrderedDict()
report["source"] = PATH
report["defined_names"] = [
    OrderedDict(name=n.name, attr_text=n.attr_text) for n in wb.defined_names.values()
]
report["sheets"] = []

for ws in wb.worksheets:
    wsv = wbv[ws.title]
    s = OrderedDict()
    s["title"] = ws.title
    s["state"] = ws.sheet_state
    s["dimensions"] = dict(
        max_row=ws.max_row, max_col=ws.max_column, min_row=ws.min_row, min_col=ws.min_column
    )
    s["merged"] = sorted(str(r) for r in ws.merged_cells.ranges)
    s["freeze_panes"] = ws.freeze_panes
    s["sheet_view"] = dict(
        show_grid_lines=getattr(ws.sheet_view, "showGridLines", None),
        zoom=getattr(ws.sheet_view, "zoomScale", None),
    )
    s["default_col_width"] = ws.sheet_format.defaultColWidth
    s["default_row_height"] = ws.sheet_format.defaultRowHeight
    s["col_widths"] = OrderedDict()
    for k, dim in sorted(ws.column_dimensions.items()):
        s["col_widths"][k] = OrderedDict(
            width=dim.width,
            hidden=dim.hidden,
            custom=dim.customWidth,
            min=dim.min,
            max=dim.max,
        )
    s["row_heights"] = OrderedDict()
    for k, dim in sorted(ws.row_dimensions.items()):
        if dim.height or dim.hidden:
            s["row_heights"][str(k)] = OrderedDict(height=dim.height, hidden=dim.hidden)
    s["data_validations"] = [
        OrderedDict(
            sqref=str(dv.sqref),
            type=dv.type,
            formula1=dv.formula1,
            formula2=dv.formula2,
            allow_blank=dv.allow_blank,
        )
        for dv in ws.data_validations.dataValidation
    ]
    s["conditional_formatting"] = [
        OrderedDict(sqref=str(cf.sqref), rules=[r.type for r in cf.rules])
        for cf in ws.conditional_formatting
    ]
    ps = ws.page_setup
    s["print"] = OrderedDict(
        orientation=ps.orientation,
        paper_size=ps.paperSize,
        fit_to_width=ps.fitToWidth,
        fit_to_height=ps.fitToHeight,
        scale=ps.scale,
        print_area=ws.print_area,
        print_title_rows=ws.print_title_rows,
        print_title_cols=ws.print_title_cols,
        margins=OrderedDict(
            left=ws.page_margins.left,
            right=ws.page_margins.right,
            top=ws.page_margins.top,
            bottom=ws.page_margins.bottom,
            header=ws.page_margins.header,
            footer=ws.page_margins.footer,
        ),
        header=ws.oddHeader.center.text if ws.oddHeader else None,
        footer=ws.oddFooter.center.text if ws.oddFooter else None,
        row_breaks=[b.id for b in ws.row_breaks.brk],
        col_breaks=[b.id for b in ws.col_breaks.brk],
    )
    cells = []
    for row in ws.iter_rows():
        for c in row:
            if c.value is None and not c.has_style:
                continue
            cells.append(cell_repr(c, c.value))
    s["cells"] = cells
    # values-only grid (formulas already evaluated by the producer) for golden comparison
    grid = OrderedDict()
    for row in wsv.iter_rows():
        for c in row:
            if c.value is not None:
                grid[c.coordinate] = c.value
    s["values"] = grid
    report["sheets"].append(s)

print(json.dumps(report, ensure_ascii=False, indent=1, default=str))
