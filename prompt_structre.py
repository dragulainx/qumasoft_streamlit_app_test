"""Map the structure of a benchmark prompt XML file.

Prints every element down to MAX_DEPTH with its line range, size in characters
and a rough token estimate (chars / 4), collapsing repeated siblings into one
row with a count. Then lists each <threat> of the current risk assessment with
its line range, status and name.

Usage: python -I scripts/prompt_structure.py test-prompt.xml [max_depth]
"""
import re
import sys
from collections import Counter

TAG = re.compile(r"<(/?)([A-Za-z_][\w\-.]*)([^>]*?)(/?)>")


def walk(text):
    """Yield (depth, name, start_line, end_line, chars, path) for every element."""
    line_starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line_of(pos):
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    stack = []
    for m in TAG.finditer(text):
        close, name, _, self_closing = m.groups()
        if close:
            while stack:
                open_name, start = stack.pop()
                if open_name == name:
                    path = "/".join(n for n, _ in stack) + "/" + name
                    yield len(stack), name, line_of(start), line_of(m.end()), m.end() - start, path
                    break
        elif self_closing:
            path = "/".join(n for n, _ in stack) + "/" + name
            yield len(stack), name, line_of(m.start()), line_of(m.end()), m.end() - m.start(), path
        else:
            stack.append((name, m.start()))


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    path = sys.argv[1]
    max_depth = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    text = open(path, encoding="utf-8").read()
    total = len(text)
    elements = sorted(walk(text), key=lambda e: (e[2], e[0]))

    print(f"{'element':60} {'lines':>13} {'chars':>8} {'~tokens':>8} {'%':>5}")
    seen = Counter()
    for depth, name, start, end, chars, el_path in elements:
        if depth > max_depth:
            continue
        seen[el_path] += 1
        if seen[el_path] > 1:
            continue
        count = sum(1 for e in elements if e[5] == el_path)
        label = "  " * depth + name + (f" (x{count})" if count > 1 else "")
        if count > 1:
            chars = sum(e[4] for e in elements if e[5] == el_path)
            end = max(e[3] for e in elements if e[5] == el_path)
        print(f"{label:60} {start:>6}-{end:<6} {chars:>8} {chars // 4:>8} {100 * chars / total:>5.1f}")

    print(f"\nTotal: {total} chars, ~{total // 4} tokens (chars/4; real tokenizers differ)\n")
    print("Threats in task_specific_context/current_risk_assessment:")
    for depth, name, start, end, chars, el_path in elements:
        if name == "threat" and "current_risk_assessment" in el_path:
            block = "\n".join(text.split("\n")[start - 1:end])
            status = re.search(r"<status>\s*<status>(\w+)", block)
            title = re.search(r"<name>(.*?)</name>", block, re.S)
            print(f"  lines {start}-{end}: [{status.group(1) if status else '?'}] {title.group(1).strip() if title else '?'}")


if __name__ == "__main__":
    main()
