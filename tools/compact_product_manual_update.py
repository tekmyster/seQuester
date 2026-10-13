from __future__ import annotations

import argparse
from pathlib import Path

from docx import Document


def remove_paragraph(paragraph) -> None:
    element = paragraph._element
    element.getparent().remove(element)
    paragraph._p = paragraph._element = None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input")
    parser.add_argument("output")
    args = parser.parse_args()

    document = Document(args.input)
    paragraphs = document.paragraphs
    removed = 0
    for index, paragraph in enumerate(paragraphs):
        if paragraph.text != "Unchanged limits and open requirements":
            continue
        if index + 1 >= len(paragraphs):
            raise RuntimeError("Limits heading has no body paragraph")
        body = paragraphs[index + 1]
        if not body.text.startswith("The recent work does not prove"):
            raise RuntimeError("Unexpected limits body")
        remove_paragraph(body)
        remove_paragraph(paragraph)
        removed = 2
        break

    if removed != 2:
        raise RuntimeError("Expected to remove the redundant limits heading and body")

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    document.save(output)
    print(f"Removed redundant limits section: {output}")


if __name__ == "__main__":
    main()
