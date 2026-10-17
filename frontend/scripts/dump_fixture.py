"""Write the Reports the frontend's unit tests read: frontend/src/lib/__fixtures__/reports.json, a list of {label, text, report}.

Run from anywhere with the project venv (needs both models and the gambling lookup files):
    .venv/bin/python frontend/scripts/dump_fixture.py

Inputs: every entry of tests/tricky_inputs.py, plus four extras the lib tests name (emoji before an OTP request, "shipping" before a real
"PIN", the bank example chip, a betting promo). Each Report is made exactly as the API makes it (analyse() then to_report()), so the tests
run on real output. meta.ms stays null: the API sets it, not to_report(). Rerun after any change to the adapter or the models.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..")
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "tests")]

from shield.core.report import to_report   # noqa: E402
from shield.core.router import analyse   # noqa: E402
from shield.links.lexical import load_url_model   # noqa: E402
from shield.messages.text_head import load_text_model   # noqa: E402
from tricky_inputs import INPUTS   # noqa: E402

OUT = os.path.join(HERE, "..", "src", "lib", "__fixtures__", "reports.json")
EXTRAS = [
    ("emoji-otp", "\U0001F4E6\U0001F4E6 Share your OTP now: http://sbi-kyc.xyz"),
    ("shipping-pin", "Your shipping update: share the PIN 4821 with our agent to confirm delivery today."),   # as tests/test_contracts.py EXTRA
    ("bank-example", "Rs.2,500.00 debited from A/c XX4821 on 14-10-26 to VPA swiggy@ybl. If this was not you, call the number on the back of "
                     "your card. Never share your OTP with anyone. -HDFC Bank"),   # the "Genuine bank alert" chip (frontend/src/components/Examples.tsx)
    ("bet365-promo", "Get a 500% welcome bonus, play now: https://www.bet365.com/"),
]


def main():
    tm, um = load_text_model(), load_url_model()
    items = [(x["id"], x["text"]) for x in INPUTS] + EXTRAS
    out = [{"label": label, "text": text, "report": to_report(text, analyse(text, tm, um)).model_dump(mode="json")} for label, text in items]
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
        f.write("\n")
    levels = {}
    for x in out:
        levels[x["report"]["level"]] = levels.get(x["report"]["level"], 0) + 1
    print(f"{len(out)} reports -> {os.path.relpath(OUT, ROOT)}  levels: {levels}")


if __name__ == "__main__":
    main()
