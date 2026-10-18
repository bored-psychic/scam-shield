"""Write the Reports the frontend's unit tests read: frontend/src/lib/__fixtures__/reports.json, a list of {label, text, report}.

Run from anywhere with the project venv (needs both models and the gambling lookup files):
    .venv/bin/python frontend/scripts/dump_fixture.py

Inputs: every entry of tests/tricky_inputs.py, plus four extras the lib tests name (emoji before an OTP request, "shipping" before a real
"PIN", the bank example chip, a betting promo), plus sender variants (D22: the real Jio promo with a P header, its bare header, a mobile
number; the KYC scam with a P header; the bank example with a T header), plus (D24) the 14 demo messages ("demo-d01" ...) and the Jio promo with a
mobile number / with an OTP request, the two cases where the P1 "Lowered from..." note must NOT show. Each Report is made exactly as the API makes it (analyse() then
to_report()), so the tests run on real output. meta.ms stays null: the API sets it, not to_report(). Rerun after any change to the adapter
or the models. The fixture keeps no sender string: a variant's label says which sender it was given, and the Report only echoes a header.
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
from demo_check import load_demo   # noqa: E402

OUT = os.path.join(HERE, "..", "src", "lib", "__fixtures__", "reports.json")
EXTRAS = [
    ("emoji-otp", "\U0001F4E6\U0001F4E6 Share your OTP now: http://sbi-kyc.xyz"),
    ("shipping-pin", "Your shipping update: share the PIN 4821 with our agent to confirm delivery today."),   # as tests/test_contracts.py EXTRA
    ("bank-example", "Rs.2,500.00 debited from A/c XX4821 on 14-10-26 to VPA swiggy@ybl. If this was not you, call the number on the back of "
                     "your card. Never share your OTP with anyone. -HDFC Bank"),   # the "Genuine bank alert" chip (frontend/src/components/Examples.tsx)
    ("bet365-promo", "Get a 500% welcome bonus, play now: https://www.bet365.com/"),
]
JIO = ("Dear User,\nYou've earned Lifetime Free\nKiwi UPI Credit Card (CC:\nJIOKIWI) on JioRecharge.\nClaim now:\nhttps://t.jio/JIOCPN/x48NuN\nT&C*\n"
       "JioCoupons")   # the real Jio promo, typed (tests/test_ocr.py JIO_TEXT)
KYC = ("Dear Customer, your SBI account will be blocked today due to pending KYC. Update now: sbi-kyc-update.top/login Share the OTP sent to your "
       "number to complete verification.")   # the "KYC update SMS" chip
JIO_CASES = [("jio-mobile-number", JIO + "\nCall 9876543210 to activate"), ("jio-otp-request", JIO + "\nShare the OTP sent to you to claim.")]   # as tests/test_links_live.py L2
SENDER_EXTRAS = [   # (label, text, sender)
    ("jio-no-sender", JIO, None), ("jio-promotional", JIO, "JM-JIOCPN-P"), ("jio-bare", JIO, "JIOCPN"), ("jio-mobile", JIO, "+91 98765 43210"),
    ("jio-other", JIO, "Jio"), ("kyc-promotional", KYC, "JM-JIOCPN-P"), ("bank-transactional", EXTRAS[2][1], "VM-HDFCBK-T"),
]


def main():
    tm, um = load_text_model(), load_url_model()
    items = ([(x["id"], x["text"], None) for x in INPUTS] + [(label, text, None) for label, text in EXTRAS + JIO_CASES] + SENDER_EXTRAS
             + [("demo-" + d["id"], d["text"], None) for d in load_demo()])
    out = [{"label": label, "text": text, "report": to_report(text, analyse(text, tm, um, sender=sender)).model_dump(mode="json")}
           for label, text, sender in items]
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
