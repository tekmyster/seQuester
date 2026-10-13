from __future__ import annotations

import argparse
from pathlib import Path

import pypdfium2 as pdfium
from PIL import Image, ImageDraw, ImageFont


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("pdf")
    ap.add_argument("output")
    ap.add_argument("--scale", type=float, default=1.67)
    ap.add_argument("--contact-columns", type=int, default=4)
    ap.add_argument("--contact-rows", type=int, default=4)
    args = ap.parse_args()
    target = Path(args.output)
    pages_dir = target / "pages"
    contacts_dir = target / "contacts"
    pages_dir.mkdir(parents=True, exist_ok=True)
    contacts_dir.mkdir(parents=True, exist_ok=True)

    pdf = pdfium.PdfDocument(args.pdf)
    page_paths: list[Path] = []
    for i, page in enumerate(pdf):
        image = page.render(scale=args.scale).to_pil().convert("RGB")
        path = pages_dir / f"page-{i + 1:03d}.png"
        image.save(path, "PNG", optimize=True)
        page_paths.append(path)

    per_sheet = args.contact_columns * args.contact_rows
    thumb_w, thumb_h, label_h, gutter = 255, 330, 24, 12
    font = ImageFont.load_default()
    for start in range(0, len(page_paths), per_sheet):
        subset = page_paths[start : start + per_sheet]
        sheet = Image.new(
            "RGB",
            (
                gutter + args.contact_columns * (thumb_w + gutter),
                gutter + args.contact_rows * (thumb_h + label_h + gutter),
            ),
            "#D7DCE2",
        )
        draw = ImageDraw.Draw(sheet)
        for offset, path in enumerate(subset):
            row, col = divmod(offset, args.contact_columns)
            x = gutter + col * (thumb_w + gutter)
            y = gutter + row * (thumb_h + label_h + gutter)
            with Image.open(path) as src:
                thumb = src.copy()
                thumb.thumbnail((thumb_w, thumb_h), Image.Resampling.LANCZOS)
                px = x + (thumb_w - thumb.width) // 2
                py = y + (thumb_h - thumb.height) // 2
                sheet.paste(thumb, (px, py))
            label = f"Page {start + offset + 1}"
            draw.text((x + 4, y + thumb_h + 5), label, fill="black", font=font)
        sheet.save(contacts_dir / f"contact-{start // per_sheet + 1:02d}.png", "PNG", optimize=True)
    print(f"Rendered {len(page_paths)} pages and {(len(page_paths) + per_sheet - 1) // per_sheet} contact sheets")


if __name__ == "__main__":
    main()
