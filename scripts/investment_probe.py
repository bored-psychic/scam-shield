"""Investment / task-scam probe (docs/opportunities/probe_results.md). Probe set only, never training or tuning.
python scripts/investment_probe.py build   -> data/probes/investment_probe.csv (git-ignored) + .sha256
python scripts/investment_probe.py score   -> data/probes/investment_probe_scored.csv + printed tables
Every text is ASCII and PII-free. `provenance`: real_cited (quoted in a cited page), real_dataset (our messages.csv, source scam_ham_india),
illustrative_cited (an example on an advocacy page), synthetic_dataset (our synth template), illustrative_authored (written here from the public
format of such alerts), constructed (written here to unit-test a rule; excluded from every headline count)."""
import hashlib, os, re, sys
import pandas as pd
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [os.path.join(ROOT, "src")]
OUT = os.path.join(ROOT, "data", "probes", "investment_probe.csv")
MB = "https://www.malwarebytes.com/blog/news/2025/03/i-spoke-to-a-task-scammer-heres-how-it-went"
SC = "https://scamcheck.tech/scams/investment-scam-india"
MH = "data/final/messages.csv (source scam_ham_india)"
# (id, label 1 scam / 0 genuine, kind, provenance, split_in_our_data, citation, text)
ROWS = [
 ("s01", 1, "task", "real_cited", "", MB, "Hello, I am a third-party agency from the UK, specializing in providing ranking and likes services for"),
 ("s02", 1, "task_pay_to_withdraw", "real_cited", "", MB, "I forgot to tell you, it takes 100usdt to complete a new round of 40/40 orders to reset 40 new orders."),
 ("s03", 1, "invest_group", "illustrative_cited", "", SC, "VIP Trading Group - NSE/BSE Tips. 95% accuracy. Last week: Rs 2.3L profit on a Rs 50K investment. Join free for 3 days. Only 5 slots left. Message us to join the ELITE group."),
 ("s04", 1, "invest_advisor", "illustrative_cited", "", SC, "Hi, I'm Priya, certified SEBI analyst. My clients made 300% in 6 months. I can help you too. Invest Rs 25,000 to start. Guaranteed 40% monthly return. No risk involved."),
 ("s05", 1, "task", "real_dataset", "test", MH, "You can work online without investment, earn 200-3000 rs a day, click the link to contact: https://wa.me/<ACCOUNT> Y2ql"),
 ("s06", 1, "task", "real_dataset", "train", MH, "Work from home and earn Rs 5000 daily by completing simple tasks, no investment low risk, message now to join."),
 ("s07", 1, "invest_group", "real_dataset", "train", MH + ", labelled 0 there; judged a scam-group lure here", "Add my assistant Rama's WhatsApp, and she will notify you of the stock name and buying and selling points on time at 2"),
 ("s08", 1, "invest_group", "real_dataset", "train", MH + ", labelled 0 there; judged a scam-group lure here", "The above are the momentum stocks recommended by Professor Sohan Sharma. If you have already purchased them, please let me know the buying price so I can provide timely advice later on. If you haven't"),
 ("s09", 1, "invest_group", "real_dataset", "train", MH + ", labelled 0 there; judged a scam-group lure here", "Falling is rising, stay calm, and join me in seizing the opportunity to buy new multi-billion stocks tomorrow."),
 ("s10", 1, "invest_group", "real_dataset", "test", MH + ", labelled 0 there; judged a scam-group lure here", "I am not comforting you because the stocks I recommended recently suffered a floating loss, but because I treat every member as a friend"),
 ("s11", 1, "task_invest", "synthetic_dataset", "train", "data/final/messages.csv (source india_fraud_final)", "VIP Level 2 Task: Invest Rs 5000 and receive Rs 7500 plus a bonus. Limited spots available!"),
 # constructed rule unit tests (kept out of the headline numbers)
 ("c01", 1, "pay_to_withdraw", "constructed", "", "written here", "Your profit of Rs 3,40,000 is ready. To withdraw it you must first pay 20% income tax of Rs 68,000 to release the funds."),
 ("c02", 1, "personal_upi", "constructed", "", "written here", "Congratulations, your VIP trading account is approved. Pay Rs 25,000 to rajesh.trade88@ybl to activate it and receive IPO allotment."),
 ("c03", 1, "app_in_message", "constructed", "", "written here", "Join our stock group. Download our trading app from https://bluechip-invest.top/app.apk to see today's sure shot calls."),
 # genuine
 ("g01", 0, "tds", "synthetic_dataset", "train", "data/final/messages.csv (source india_fraud_final)", "Hello Customer, TDS of Rs 450.00 has been deducted by BANK OF BARODA for Q3 of FY 2025-26 on PAN XXXXX1122X. - IT Dept"),
 ("g02", 0, "tds", "synthetic_dataset", "train", "data/final/messages.csv (source india_fraud_final)", "Dear Customer, TDS of Rs 450.00 has been deducted by BANK OF BARODA for Q3 of FY 2025-26 on PAN XXXXX1122X. - IT Dept For queries, call our helpline."),
 ("g03", 0, "broker_funds", "illustrative_authored", "", "written here", "Dear Investor, Rs 25,000.00 has been added to your trading account via UPI on 14-Oct-2026. Available margin: Rs 25,000.00. Never share your PIN or OTP with anyone."),
 ("g04", 0, "depository", "illustrative_authored", "", "written here", "CDSL: Debit in a/c XXXX1234 for 10 units of INFY on 14OCT. If not done by you, contact your broker immediately."),
 ("g05", 0, "mutual_fund", "illustrative_authored", "", "written here", "Your SIP of Rs 5,000 for Example Mutual Fund Growth Plan, folio 12345, was processed on 05-Oct-2026. Units allotted: 38.214."),
 ("g06", 0, "exchange_alert", "illustrative_authored", "", "written here", "Dear Investor, you have traded on the equity segment today. Your contract note will be sent to your registered email. If this was not you, contact your broker. -NSE"),
 ("g07", 0, "ipo", "illustrative_authored", "", "written here", "Your IPO application for ExampleTech Ltd was submitted. A UPI mandate request of Rs 14,850 has been sent to your UPI app. Approve it before 5 PM on 16-Oct-2026."),
 ("g08", 0, "withdrawal", "illustrative_authored", "", "written here", "Withdrawal of Rs 10,000 from your trading account is processed. Funds will reach your bank account ending 4321 within 24 hours. Charges are shown in your contract note."),
 ("g09", 0, "app_mention", "illustrative_authored", "", "written here", "Your Q2 FY26 ledger statement is ready. Download it from the official broker app or the web console. We never ask you to install apps from links."),
 ("g10", 0, "broker_upi", "illustrative_authored", "", "written here", "To add funds, pay by UPI to examplebroker.brk@validicici from your own bank app. Funds reflect within minutes. Do not pay any other account."),
]
RX = {   # the three proposed rules, as first-pass regexes (they run on the raw text, as the app would)
 "pay_to_withdraw": re.compile(r"(?:(?:pay|deposit|clear|submit)\b[^.]{0,60}\b(?:tax|fee|fees|charge|charges|commission|deposit)\b[^.]{0,60}\b(?:withdraw|release|credit)"
    r"|(?:withdraw\w*|release)\b[^.]{0,60}\b(?:you|must|need|require\w*)\b[^.]{0,40}\b(?:pay|deposit|tax|fee|charge)"
    r"|\b(?:tax|fee|charge|deposit)\b[^.]{0,40}\b(?:to|before|for)\b[^.]{0,20}\b(?:withdraw\w*|release)"
    r"|\b(?:pay|deposit|send)\b[^.]{0,40}\busdt\b|\b\d+\s*usdt\b[^.]{0,40}\b(?:complete|reset|withdraw|unlock)|\b(?:pay|deposit|send)\b[^.]{0,30}\bto\s+(?:withdraw|release|unlock)\b)", re.I),
}
TRADE = re.compile(r"\b(?:trading|invest\w*|stock\w*|ipo|demat|broker|shares?|nse|bse|profit|portfolio|vip group)\b", re.I)
UPI = re.compile(r"\b[\w.\-]{2,}@[a-z][a-z0-9]{1,}\b", re.I)
VALID = re.compile(r"@valid[a-z]+\b", re.I)
APP = re.compile(r"(?:\b(?:download|install)\b[^.]{0,50}\b(?:app|apk|application)\b|\.apk\b)", re.I)
APP_SAFE = re.compile(r"\b(?:official|play ?store|app ?store)\b", re.I)
def rule_pay_to_withdraw(t): return bool(RX["pay_to_withdraw"].search(t))
def rule_trading_upi(t):
    if not TRADE.search(t): return False
    return any(not VALID.search(m.group(0)) and not re.search(r"\.(?:com|in|net|org)$", m.group(0), re.I) for m in UPI.finditer(t))
def rule_app_in_message(t): return bool(TRADE.search(t) and APP.search(t) and not (APP_SAFE.search(t)) ) or bool(re.search(r"\.apk\b", t, re.I))
RULES = {"pay_to_withdraw": rule_pay_to_withdraw, "trading_upi_not_valid": rule_trading_upi, "app_in_message": rule_app_in_message}

def build():
    df = pd.DataFrame(ROWS, columns=["id", "label", "kind", "provenance", "split_in_our_data", "citation", "text"])
    assert df.text.map(str.isascii).all()
    df.to_csv(OUT, index=False)
    h = hashlib.sha256(open(OUT, "rb").read()).hexdigest()
    open(OUT.replace(".csv", ".sha256"), "w").write(h + "  investment_probe.csv\n")
    print(len(df), df.provenance.value_counts().to_dict(), h)

def score():
    from shield.core.router import analyse, LEVELS
    from shield.messages.text_head import load_text_model
    from shield.links.lexical import load_url_model
    tm, um = load_text_model(), load_url_model()
    df = pd.read_csv(OUT)
    rec = []
    for r in df.itertuples():
        a = analyse(r.text, tm, um)
        rec.append({"muril_score": a["text_score"], "level": a["level"], "verdict": LEVELS[a["level"]] if a["level"] is not None else "none", "tags": ",".join(k for k, v in a["tags"].items() if v) if isinstance(a["tags"], dict) else str(a["tags"]),
                    **{k: int(f(r.text)) for k, f in RULES.items()}})
    out = pd.concat([df, pd.DataFrame(rec)], axis=1)
    out["rules_any"] = out[list(RULES)].max(axis=1)
    out.to_csv(OUT.replace(".csv", "_scored.csv"), index=False)
    print(getattr(tm, "name", type(tm).__name__))
    print(out.drop(columns=["text", "citation"]).to_string())
if __name__ == "__main__":
    {"build": build, "score": score}[sys.argv[1]]()
