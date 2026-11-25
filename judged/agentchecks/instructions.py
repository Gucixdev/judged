"""Instruction files an agent obeys (CLAUDE.md, AGENTS.md, .cursorrules, skills): text a human cannot see is an attack, and so is a repo that
tells the agent to ignore what you told it. Names the file, line and code point, never the surrounding text."""
import re

from . import repos, verdict

NAME, ORDER = "instructions", 30
NAMES = ("CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules", ".github/copilot-instructions.md", ".claude/CLAUDE.md")
GLOBS = (".claude/skills/*/SKILL.md", ".claude/commands/*.md", ".claude/agents/*.md", ".cursor/rules/*")
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
TAGS = set(range(0xE0000, 0xE0080))
INVISIBLE = {0x200B, 0x200C, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x00AD, 0x180E}
PHRASES = re.compile(r"ignore (all |any |the )?(previous|prior|above) (instructions|rules)|disregard (your|all|the) (instructions|rules)|"
                     r"do not (tell|inform|mention (this )?to) the user|without (telling|informing) the user|you are no longer bound", re.I)


def hidden(text: str) -> list:
    """[(level, line, code point)]: bidi controls and tag characters hide or reorder text (fail); zero-width and soft hyphens are
    often pasted by accident (warn). A byte order mark at the very start and a joiner inside an emoji are normal."""
    out = []
    for n, line in enumerate(text.split("\n"), 1):
        flag = False                      # inside a subdivision flag: U+1F3F4 followed by tag characters
        for i, ch in enumerate(line):
            c = ord(ch)
            flag = c == 0x1F3F4 or (flag and c in TAGS)
            if c in BIDI or (c in TAGS and not flag):
                out.append(("fail", n, c))
            elif c in INVISIBLE and not (c == 0xFEFF and n == 1 and i == 0):
                out.append(("warn", n, c))
    return out


def check(cfg, env) -> list:
    home, files = env.home(), [f"{env.home()}/.claude/CLAUDE.md"]
    for r in repos(cfg, env):
        files += [f"{r}/{n}" for n in NAMES] + [p for g in GLOBS for p in env.glob(f"{r}/{g}")]
    for g in GLOBS:
        files += env.glob(f"{home}/{g}")
    f, seen = [], 0
    for path in dict.fromkeys(files):
        text = env.read(path)
        if text is None:
            continue
        seen += 1
        label = path.replace(home, "~", 1)
        f += [(lv, f"{label} line {n} holds U+{c:04X}" + (" (hides or reorders text)" if lv == "fail" else "")) for lv, n, c in hidden(text)[:3]]
        found = [text[:m.start()].count("\n") + 1 for m in PHRASES.finditer(text)]
        if found:
            f.append(("warn", f"{label} line {found[0]} tells the agent to disregard instructions or hide something from you (may be documentation about injection)"))
    if not seen:
        return []
    return [verdict("agents.instructions", "agent instruction files", f, f"{seen} file(s) read, no hidden characters, no override phrases")]
