"""AI provider keys left in plain text: shell start-up files and .env files in the repos. Prints the variable and the file, never the value."""
import re

from . import M_AGENTS, repos, verdict

NAME, ORDER = "envkeys", 40
KEY = re.compile(r"^\s*(?:export\s+)?((?:ANTHROPIC|OPENAI|GEMINI|GOOGLE|GROQ|MISTRAL|COHERE|OPENROUTER|XAI|DEEPSEEK|PERPLEXITY|TOGETHER|FIREWORKS|REPLICATE|"
                 r"AZURE_OPENAI|HUGGINGFACE|HF)[A-Z_]*(?:KEY|TOKEN))\s*=\s*(.*?)\s*$")
RC = (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv", ".config/fish/config.fish", ".config/environment.d/*.conf")
ENVFILES = (".env", ".env.local", ".env.development", ".env.production")


def literal_keys(text: str) -> list:
    out = []
    for line in text.split("\n"):
        m = KEY.match(line)
        if m:
            v = m.group(2).strip("'\"")
            if len(v) >= 8 and not v.startswith(("$", "<", "`")) and "${" not in v and "$(" not in v:
                out.append(m.group(1))
    return out


def check(cfg, env) -> list:
    home, out = env.home(), []
    for pat in RC:
        for path in env.glob(f"{home}/{pat}"):
            names = literal_keys(env.read(path) or "")
            if names:
                mode, f = env.mode(path), []
                f.append(("warn", f"{', '.join(sorted(set(names)))} written out in plain text: every program you start can read it, agents included; keep it in a file mode 600 that the shell sources"))
                if mode is not None and mode & 0o044:
                    f.append(("fail", f"the file is readable by other users (mode {mode:o})"))
                out.append(verdict(f"agents.envkeys.{path.replace(home, '~', 1)}", f"AI keys in {path.replace(home, '~', 1)}", f, ""))
    for r in repos(cfg, env):
        for n in ENVFILES:
            path = f"{r}/{n}"
            names = literal_keys(env.read(path) or "")
            if not names:
                continue
            f = []
            rc, _ = env.git(r, "ls-files", "--error-unmatch", n)
            if rc == 0:
                f.append(("fail", f"{', '.join(sorted(set(names)))} in {n}, which git tracks: the key is in the repository history"))
            else:
                rc, _ = env.git(r, "check-ignore", "-q", n)
                if rc == 1:
                    f.append(("fail", f"{', '.join(sorted(set(names)))} in {n}, which is not in .gitignore"))
                elif rc != 0:
                    f.append(("warn", f"{', '.join(sorted(set(names)))} in {n}: could not ask git whether it is ignored"))
                else:
                    f.append(("warn", f"{', '.join(sorted(set(names)))} in {n} (ignored by git, still plain text)"))
            mode = env.mode(path)
            if mode is not None and mode & 0o044:
                f.append(("fail", f"{n} is readable by other users (mode {mode:o})"))
            out.append(verdict(f"agents.envkeys.{r.rstrip('/').rsplit('/', 1)[-1]}.{n}", f"AI keys in {r.rstrip('/').rsplit('/', 1)[-1]}/{n}", f, ""))
    return out
