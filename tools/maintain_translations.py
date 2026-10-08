#!/usr/bin/env python3
"""Merge a hook missing-log and keep ida_lang.txt sorted by intent."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


ENTRY_RE = re.compile(r'^L"((?:\\.|[^"\\])*)",L"((?:\\.|[^"\\])*)",\s*$')
CJK_RE = re.compile(r"[\u3400-\u9fff]")
ONLY_VALUE_RE = re.compile(r"^[\s\dA-Fa-f:+\-.]+$")
VERSION_RE = re.compile(r"^(?:IDA v|Version )\d")
SHORTCUT_RE = re.compile(
    r"^(?:(?:Ctrl|Alt|Shift|Meta)\+)+(?:[A-Za-z0-9.+-]+|Backtab|Tab|Enter|Up|Down|Left|Right|F\d+)$"
    r"|^Numpad\+.+$"
)
# IDA uses slash-delimited action/option paths as internal lookup keys.  They may
# eventually reach a Qt setter, but translating them can change tree grouping
# semantics before the visible leaf label is rendered.
STRUCTURAL_PATH_RE = re.compile(
    r"^(?:Columns|Data format|Edit|File|Help|Jump|Lumina|Search|Text|View)/"
)


def unescape(value: str) -> str:
    result: list[str] = []
    index = 0
    escapes = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
    while index < len(value):
        if value[index] == "\\" and index + 1 < len(value):
            result.append(escapes.get(value[index + 1], value[index + 1]))
            index += 2
        else:
            result.append(value[index])
            index += 1
    return "".join(result)


def escape(value: str) -> str:
    return (value.replace("\\", "\\\\")
                 .replace('"', '\\"')
                 .replace("\n", "\\n")
                 .replace("\r", "\\r")
                 .replace("\t", "\\t"))


def read_entries(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = ENTRY_RE.fullmatch(line)
        if not match:
            raise ValueError(f"{path}:{number}: invalid translation entry")
        source, target = map(unescape, match.groups())
        previous = entries.get(source)
        if previous is not None and previous != target:
            raise ValueError(f"{path}:{number}: conflicting duplicate: {source!r}")
        entries[source] = target
    return entries


def is_runtime_noise(text: str) -> bool:
    """Exclude values that vary per database/session or are translated feedback."""
    if CJK_RE.search(text):
        return True
    # QFontMetrics::elidedText() can feed a paint hook a derived label such as
    # "Database sn… &manager...".  It is not a stable source string.
    if "…" in text:
        return True
    if re.fullmatch(r"X{4,}", text):
        return True
    # Do not mistake shortcuts such as Ctrl+A or Alt+1 for symbol/address
    # feedback merely because their suffix is a hexadecimal character.
    if SHORTCUT_RE.fullmatch(text):
        return False
    if "/home/" in text or text.startswith(("IDA - ", "Navigator Scale: ", "Disk: ")):
        return True
    if text.startswith(("Packing the database\n", "Unpacking the database\n")):
        return True
    if VERSION_RE.match(text) or ONLY_VALUE_RE.fullmatch(text):
        return True
    if re.fullmatch(r"(?:sub|loc|off|byte|word|dword|qword)_[0-9A-Fa-f]+", text):
        return True
    if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*[+:][0-9A-Fa-fx]+(?: \([0-9A-Fa-f]+\))?", text):
        return True
    return False


def is_structural_path(text: str) -> bool:
    return STRUCTURAL_PATH_RE.match(text) is not None


def render(entries: dict[str, str]) -> str:
    translated = sorted((item for item in entries.items() if item[0] != item[1]),
                        key=lambda item: (item[0].casefold(), item[0]))
    preserved = sorted((item for item in entries.items() if item[0] == item[1]),
                       key=lambda item: (item[0].casefold(), item[0]))

    lines = [
        "# IDA Pro 9.4 SP1 简体中文 UI 词典",
        "# 格式：L\"界面原文\",L\"显示文本\",",
        "# 本文件只用于 Qt UI 显示层；不要加入反汇编内容、数据库数据或动态路径。",
        "",
        "# =============================================================================",
        "# [TRANSLATED] 已汉化界面文案（按原文排序）",
        "# =============================================================================",
    ]
    lines.extend(f'L"{escape(source)}",L"{escape(target)}",' for source, target in translated)
    lines.extend([
        "",
        "# =============================================================================",
        "# [KEEP-ORIGINAL] 有意保留原文的术语、品牌、快捷键及格式标识（按原文排序）",
        "# 等值映射用于阻止这些内容反复进入 ida_missing_translations.txt。",
        "# =============================================================================",
    ])
    lines.extend(f'L"{escape(source)}",L"{escape(target)}",' for source, target in preserved)
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dictionary", type=Path, default=Path("ida_lang.txt"))
    parser.add_argument("--missing", type=Path)
    parser.add_argument("--updates", type=Path,
                        help="translation entries that override the main dictionary")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    entries = read_entries(args.dictionary)
    if args.updates:
        entries.update(read_entries(args.updates))
    added = ignored = structural = 0
    if args.missing:
        for source in read_entries(args.missing):
            if source in entries:
                continue
            if is_runtime_noise(source):
                ignored += 1
                continue
            entries[source] = source
            added += 1

    # These are identifiers, not display copy.  Keep an explicit identity entry
    # so they neither get translated nor reappear in the missing-string log.
    for source, target in list(entries.items()):
        if is_structural_path(source) and source != target:
            entries[source] = source
            structural += 1

    output = render(entries)
    if args.check:
        if args.dictionary.read_text(encoding="utf-8") != output:
            print(f"{args.dictionary} needs formatting")
            return 1
    else:
        args.dictionary.write_text(output, encoding="utf-8")

    translated = sum(source != target for source, target in entries.items())
    preserved = len(entries) - translated
    print(
        f"translated={translated} keep_original={preserved} added={added} "
        f"ignored={ignored} structural_preserved={structural}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
