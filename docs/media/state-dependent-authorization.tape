Output state-dependent-authorization.gif
Set Width 1000
Set Height 620
Set FontSize 18
Set Padding 16
Set Theme "Dracula"
Set TypingSpeed 20ms

Type "clear\n"
Sleep 400ms

Type "printf '\\e[1;36m╔══════════════════════════════════════════════════════════╗\\e[0m\\n'\n"
Type "printf '\\e[1;36m║  OxDeAI  -  State-dependent authorization                ║\\e[0m\\n'\n"
Type "printf '\\e[1;36m║  Same intent · Different state · Different decision       ║\\e[0m\\n'\n"
Type "printf '\\e[1;36m╚══════════════════════════════════════════════════════════╝\\e[0m\\n'\n"
Sleep 900ms

Type "printf '\\n\\e[90m── scene 1 ────────────────────────────────────────────────\\e[0m\\n'\n"
Type "printf '\\e[1m❯  propose: provision_gpu(amount=40)\\e[0m\\n'\n"
Sleep 350ms
Type "printf '   \\e[90m→ evaluating: intent + state + policy\\e[0m\\n'\n"
Sleep 450ms
Type "printf '   \\e[1;32m→ decision  : ALLOW\\e[0m\\n'\n"
Type "printf '   \\e[32m→ reason    : within budget  (0 → 40 of 100)\\e[0m\\n'\n"
Type "printf '   \\e[90m→ execution : provision_gpu() called\\e[0m\\n'\n"
Type "printf '   \\e[90m→ state     : gpu_allocated = 40\\e[0m\\n'\n"
Sleep 800ms

Type "printf '\\n\\e[90m── scene 2 ────────────────────────────────────────────────\\e[0m\\n'\n"
Type "printf '\\e[1m❯  propose: provision_gpu(amount=40)\\e[0m\\n'\n"
Sleep 350ms
Type "printf '   \\e[90m→ evaluating: intent + state + policy\\e[0m\\n'\n"
Sleep 450ms
Type "printf '   \\e[1;32m→ decision  : ALLOW\\e[0m\\n'\n"
Type "printf '   \\e[32m→ reason    : within budget  (40 → 80 of 100)\\e[0m\\n'\n"
Type "printf '   \\e[90m→ execution : provision_gpu() called\\e[0m\\n'\n"
Type "printf '   \\e[90m→ state     : gpu_allocated = 80\\e[0m\\n'\n"
Sleep 800ms

Type "printf '\\n\\e[90m── scene 3 ────────────────────────────────────────────────\\e[0m\\n'\n"
Type "printf '\\e[1m❯  propose: provision_gpu(amount=40)\\e[0m\\n'\n"
Sleep 350ms
Type "printf '   \\e[90m→ evaluating: intent + state + policy\\e[0m\\n'\n"
Sleep 450ms
Type "printf '   \\e[1;31m→ decision  : DENY\\e[0m\\n'\n"
Type "printf '   \\e[31m→ reason    : budget exceeded  (80 + 40 > 100)\\e[0m\\n'\n"
Type "printf '   \\e[90m→ execution : NOT REACHED\\e[0m\\n'\n"
Sleep 800ms

Type "printf '\\n\\e[90m── verification ───────────────────────────────────────────\\e[0m\\n'\n"
Type "printf '\\e[1m❯  verifyEnvelope(strict)\\e[0m\\n'\n"
Sleep 500ms
Type "printf '   \\e[1;32m→ result: ok  - all transitions auditable\\e[0m\\n'\n"
Sleep 900ms

Type "printf '\\n\\e[1;37mSame intent.  Different state.  Deterministic decision.\\e[0m\\n'\n"
Sleep 1200ms
