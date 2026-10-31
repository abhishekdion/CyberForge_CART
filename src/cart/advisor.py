"""AI Remediation & Patch Advisor (judge requirement 3).

Generates plain-English advisories and concrete code/config patches for
findings. Fully rule-based and deterministic: the same finding always
produces the same advisory — an LLM may only re-word, never author patches
(determinism owns state; LLM output is advisory only).

Works best on CONFIRMED findings, but advise() never mutates finding state.
"""

from __future__ import annotations

import json
import re
import sqlite3

# Whole-word matching of unsafe libc functions mentioned in a summary/excerpt.
_UNSAFE_WORD_RE = re.compile(r"\b(strcpy|gets|system|sprintf|popen|strcat)\b")

# Rule-based remediation templates per finding_type.
_PATCH_EXAMPLES: dict[str, dict[str, str]] = {
    "web_form_endpoint": {
        "title": "Unhardened web form endpoint",
        "plain_english_summary": (
            "A web form was exposed on the target application. Forms are a "
            "primary attack surface: without validation, CSRF protection and "
            "parameterised database queries, each field can carry injection "
            "payloads or forged submissions."
        ),
        "impact": (
            "An attacker can submit crafted input to trigger SQL injection, "
            "stored XSS or forged actions on behalf of authenticated users."
        ),
        "recommended_fix": (
            "1. Validate every input server-side with a strict allow-list "
            "(type, length, format). 2. Require a per-session CSRF token on "
            "every state-changing request. 3. Use parameterised SQL queries "
            "(prepared statements) — never string-concatenate user input into "
            "SQL. 4. Encode output on render to prevent XSS."
        ),
        "patch_example": (
            "```python\n"
            "# Flask example: validation + CSRF + parameterised SQL\n"
            "from flask import Flask, request, session, abort\n"
            "import sqlite3\n\n"
            "app = Flask(__name__)\n"
            "app.secret_key = os.environ['APP_SECRET_KEY']\n\n"
            "def _validate(username: str, password: str) -> None:\n"
            "    if not (3 <= len(username) <= 32 and username.isalnum()):\n"
            "        abort(400)\n"
            "    if not (8 <= len(password) <= 128):\n"
            "        abort(400)\n\n"
            "def _check_csrf() -> None:\n"
            "    token = request.form.get('csrf_token', '')\n"
            "    if not token or token != session.get('csrf_token'):\n"
            "        abort(403)\n\n"
            "@app.route('/login', methods=['POST'])\n"
            "def login():\n"
            "    _check_csrf()\n"
            "    _validate(request.form['username'], request.form['password'])\n"
            "    conn = sqlite3.connect('app.db')\n"
            "    # Parameterised query — user input never becomes SQL text\n"
            "    row = conn.execute(\n"
            '        "SELECT id FROM users WHERE username = ? AND pw_hash = ?",\n'
            "        (request.form['username'], pw_hash(request.form['password'])),\n"
            "    ).fetchone()\n\n"
            "# NEVER do this:\n"
            "# f\"SELECT id FROM users WHERE username = '{username}'\"\n"
            "```"
        ),
    },
    "binary_unsafe_function": {
        "title": "Dangerous libc function use in binary",
        "plain_english_summary": (
            "The analysed binary contains one or more dangerous libc "
            "functions. These functions perform no bounds checking, so an "
            "attacker who controls their input can overflow buffers, corrupt "
            "memory or execute commands."
        ),
        "impact": (
            "Buffer overflows leading to crashes (denial of service) or "
            "remote code execution with the privileges of the binary."
        ),
        "recommended_fix": (
            "Replace the unsafe calls: strcpy -> strlcpy/strncpy (or use "
            "snprintf), gets -> fgets with an explicit buffer limit, "
            "sprintf -> snprintf, strcat -> strlcat/snprintf, and popen/system "
            "-> exec-variants that take an argument array after allow-listing "
            "the command. Rebuild with warnings (-Wall -Wextra) and compiler "
            "hardening (-fstack-protector-strong, FORTIFY_SOURCE) enabled."
        ),
        "patch_example": (
            "```c\n"
            "/* BEFORE (overflow-prone): */\n"
            "strcpy(dest, input);\n"
            "gets(buf);\n"
            'sprintf(buf, "Hello %s", name);\n'
            "strcat(dst, src);\n"
            "system(user_cmd);\n"
            'popen(user_cmd, "r");\n\n'
            "/* AFTER (bounded, whole buffer known): */\n"
            "char dest[BUF_SIZE];\n"
            "strncpy(dest, input, sizeof(dest) - 1);  /* or strlcpy */\n"
            "dest[sizeof(dest) - 1] = '\\0';\n\n"
            "char buf[BUF_SIZE];\n"
            "if (fgets(buf, sizeof(buf), stdin) == NULL) {\n"
            "    return; /* reject read error */\n"
            "}\n\n"
            'snprintf(buf, sizeof(buf), "Hello %s", name);\n\n'
            'snprintf(dst, sizeof(dst), "%s%s", dst, src); /* safe concat */\n\n'
            "/* Never pass raw user input to a shell. Allow-list, then: */\n"
            "pid_t pid = fork();\n"
            "if (pid == 0) {\n"
            '    execl("/usr/bin/allowed", "allowed", arg1, arg2, (char *)NULL);\n'
            "    _exit(127); /* exec failed */\n"
            "}\n"
            "```"
        ),
    },
    "binary_hardcoded_credential": {
        "title": "Hard-coded credential in binary",
        "plain_english_summary": (
            "A password, token or API key was embedded directly in the "
            "binary. Anyone who obtains the file can extract it — strings "
            "utilities retrieve embedded secrets in seconds."
        ),
        "impact": (
            "Credential theft leading to unauthorised access to the systems "
            "or services that accept this secret, and no easy rotation path."
        ),
        "recommended_fix": (
            "Do not compile secrets into binaries. Read them from "
            "environment variables at startup, or fetch them at runtime from "
            "a secret manager / key vault (e.g. HashiCorp Vault, AWS Secrets "
            "Manager, Azure Key Vault) with short-lived leases. Rotate the "
            "exposed credential immediately and audit its usage history."
        ),
        "patch_example": (
            "```python\n"
            '# BEFORE: PASSWORD = "Sup3rS3cret!"   # baked into the file\n'
            "# AFTER: read from environment or a secret manager\n"
            "import os\n"
            "PASSWORD = os.environ.get('APP_PASSWORD')\n"
            "if not PASSWORD:\n"
            "    raise RuntimeError('APP_PASSWORD not set; refusing to start')\n\n"
            "# Preferred: short-lived lease from a vault\n"
            "# secret = vault_client.read_latest('kv/credentials/app')\n"
            "```"
        ),
    },
    "ctf_planted_flag": {
        "title": "Planted CTF flag captured",
        "plain_english_summary": (
            "One of the competition's planted flags was recovered by the "
            "assessment: the host exposed the flag value where the scanner "
            "could read it (page body, HTML comment, HTTP header or binary "
            "strings)."
        ),
        "impact": (
            "Confirms the intended challenge path is solvable. If the flag "
            "is visible to unauthenticated crawlers it may also be leaked to "
            "untrusted users, revoking the challenge's difficulty."
        ),
        "recommended_fix": (
            "For the competition: record the flag capture as confirmed "
            "points for the participating team. For the lab owners: remove "
            "the flag from publicly-readable locations (serve it only after "
            "the intended exploitation step), revoke access to any file or "
            "endpoint that leaked it prematurely, and rotate the flag value "
            "if it must stay secret."
        ),
        "patch_example": (
            "```nginx\n"
            "# BEFORE: flag served to everyone in an HTML comment\n"
            "# <!-- flag{some-secret} -->\n\n"
            "# AFTER: flag endpoint gated behind the intended exploit marker\n"
            "location = /flag.txt {\n"
            "    deny all;                     # default deny\n"
            "    # 192.168.13.37 = lab scoring proxy / authenticated session\n"
            "    allow 192.168.13.37;\n"
            "    satisfy all;\n"
            "}\n"
            "```\n"
            "Operator actions: (1) log the capture in the run report, "
            "(2) revoke public read access to the leaking location, "
            "(3) rotate the flag value in the scoring system."
        ),
    },
}

_DEFAULT_TEMPLATE = {
    "title": "Finding requires defence-in-depth review",
    "plain_english_summary": (
        "The assessment produced a finding that has no specific rule-based "
        "remediation template yet. Treat it as a weakness indicator and "
        "review the class of issue it belongs to."
    ),
    "impact": (
        "Depends on the underlying weakness; unaddressed findings are a "
        "potential foothold in an attacker chain."
    ),
    "recommended_fix": (
        "Apply general defence-in-depth: minimise the exposed attack surface "
        "(firewall allow-lists, disable unused services), enforce "
        "authentication and least privilege, keep components patched, "
        "validate all input, log and alert on anomalous activity, and "
        "re-assess after each fix."
    ),
    "patch_example": (
        "```bash\n"
        "# Host-level defence-in-depth example\n"
        "# 1. Restrict the service to the lab subnet\n"
        "ufw allow from 192.168.10.0/24 to any port 80\n"
        "# 2. Disable unused services\n"
        "systemctl disable --now exampled\n"
        "# 3. Confirm the fix\n"
        "ufw status verbose && ss -tlnp\n"
        "```"
    ),
}


def _unsafe_function_patch(func_name: str) -> str:
    """Targeted single-function patch snippet."""
    snippets = {
        "strcpy": (
            "/* strcpy -> bounded copy: */\n"
            "char dest[BUF_SIZE];\n"
            "strncpy(dest, input, sizeof(dest) - 1);\n"
            "dest[sizeof(dest) - 1] = '\\0';  /* or use strlcpy */"
        ),
        "gets": (
            "/* gets -> fgets with explicit limit (gets is unfixable): */\n"
            "char buf[BUF_SIZE];\n"
            "if (fgets(buf, sizeof(buf), stdin) == NULL) { return -1; }"
        ),
        "sprintf": (
            "/* sprintf -> snprintf (bounds + format control): */\n"
            'snprintf(buf, sizeof(buf), "Hello %s", name);'
        ),
        "strcat": (
            "/* strcat -> strlcat or bounded snprintf: */\n"
            'snprintf(dst, sizeof(dst), "%s%s", dst, src);'
        ),
        "system": (
            "/* system -> allow-list + exec with argument array: */\n"
            "if (!allowed_command(user_cmd)) return -1;\n"
            "pid_t pid = fork();\n"
            "if (pid == 0) {\n"
            '    execv("/usr/bin/allowed", argv);\n'
            "    _exit(127);\n"
            "}"
        ),
        "popen": (
            "/* popen -> static command + execv (no shell metacharacters): */\n"
            "int pipefd[2];\n"
            "pipe(pipefd);\n"
            "pid_t pid = fork();\n"
            "if (pid == 0) {\n"
            "    dup2(pipefd[1], STDOUT_FILENO);\n"
            '    execv("/usr/bin/needed", argv);  /* argv is fixed, not user text */\n'
            "    _exit(127);\n"
            "}"
        ),
    }
    return snippets.get(func_name, "")


class RemediationAdvisor:
    """Generates plain-English advisories and concrete code/config patches
    for confirmed findings.

    Deterministic and rule-based: templates keyed by finding_type, with
    small extra signals parsed from the finding summary and evidence
    excerpts to tailor the patch (e.g. which unsafe function was found).
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def advise(self, finding_id: str) -> dict[str, str]:
        """Build a remediation advisory dict for one finding."""
        row = self.conn.execute(
            "SELECT finding_id, finding_type, severity, status, summary "
            "FROM findings WHERE finding_id=?",
            (finding_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"finding {finding_id} not found")

        finding_type = row[1]
        severity = row[2]
        status = row[3]
        summary = row[4]

        template = _PATCH_EXAMPLES.get(finding_type, _DEFAULT_TEMPLATE)
        advisory: dict[str, str] = {
            "finding_id": finding_id,
            "title": template["title"],
            "plain_english_summary": template["plain_english_summary"],
            "impact": template["impact"],
            "recommended_fix": template["recommended_fix"],
            "patch_example": template["patch_example"],
        }

        # Tailor with per-finding signals
        if finding_type == "binary_unsafe_function":
            funcs = self._collect_unsafe_functions(finding_id, summary)
            specificity: list[str] = []
            for fn in funcs:
                patch = _unsafe_function_patch(fn)
                if patch:
                    specificity.append(f"- `{fn}`: {patch}")
            if specificity:
                advisory["patch_example"] = "```c\n" + "\n\n".join(specificity) + "\n```"
        elif finding_type == "binary_hardcoded_credential":
            if "password" in (summary + json.dumps(self._evidence(finding_id))).lower():
                advisory["impact"] += " The exposed password grants direct login until rotated."
        elif finding_type == "ctf_planted_flag":
            advisory["recommended_fix"] = (
                "Record the capture in the run report (flag already confirmed "
                "as evidence). Then revoke whatever access leaked the flag "
                "early and rotate the flag value if uniqueness matters."
            )

        # Lifecycle-aware note (advisory only — never mutates state)
        if status == "candidate":
            advisory["plain_english_summary"] += (
                " Caution: this finding is still a CANDIDATE. Provisionally "
                "treat the advisory as guidance until the Verification "
                "Service confirms or rejects it."
            )
        elif status == "confirmed":
            advisory["plain_english_summary"] += (
                " This finding was CONFIRMED by the Verification Service."
            )
        if severity:
            advisory["impact"] = f"[severity: {severity}] " + advisory["impact"]
        return advisory

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _evidence(self, finding_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT evidence_id, source_tool, artifact_path, excerpt "
            "FROM evidence WHERE finding_id=?",
            (finding_id,),
        ).fetchall()
        return [
            {
                "evidence_id": r[0],
                "source_tool": r[1],
                "artifact_path": r[2],
                "excerpt": r[3],
            }
            for r in rows
        ]

    def _collect_unsafe_functions(self, finding_id: str, summary: str) -> list[str]:
        """Extract mentioned unsafe function names from summary + evidence."""
        texts = [summary]
        texts.extend(ev["excerpt"] for ev in self._evidence(finding_id))
        funcs: list[str] = []
        for text in texts:
            for match in _UNSAFE_WORD_RE.findall(text):
                if match not in funcs:
                    funcs.append(match)
        return funcs
