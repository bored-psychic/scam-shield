import os
os.environ.setdefault("GRADIO_ANALYTICS_ENABLED", "False")   # local-first: no telemetry from the UI library
import argparse, html
import pandas as pd
import gradio as gr
from textprep import MAX_CHARS
# Detection logic lives in src/shield/ (moved out of this file verbatim). analyse, load_text_model, load_url_model, cred_requests and
# tactic_tags are imported here so tests/ can keep calling them as `app.<name>`.
from shield.core.verdict import LEVELS
from shield.core.router import analyse
from shield.messages.text_head import load_text_model
from shield.messages.rules import cred_requests
from shield.messages.tactics import tactic_tags
from shield.links.lexical import load_url_model
from shield.links.platforms import CANT_VERIFY, CANT_JUDGE

# MVP Gradio app: paste a message, email or link -> risk level, tactic tags, top n-grams, URL feature breakdown.
#   python src/app.py [--port 7860]         (run from the project root; serves on 127.0.0.1 only)
#
# Text head: the TF-IDF + logistic regression baseline, saved by `python src/baseline.py --save models/text_baseline.joblib`. It reads
# textprep.model_text(text): links replaced by <URL>, so the link itself is judged only by the URL head below.
# URL head: models/url_head.joblib (host-only gradient boosting from url_head.py). Links are only parsed as strings,
# never fetched (CLAUDE.md rule 8), and nothing the user pastes is logged or stored.
#
# What the numbers are NOT. Both scores are uncalibrated model outputs; the three levels come from thresholds chosen on the
# validation split (never test). Combining the two heads is a placeholder rule (fuse()) until the fusion model exists.
# Tactic tags are hand-written regexes: they explain the message, they do not feed the score.
GRAM_COLS = ["n-gram (_ = word edge)", "pushes toward", "contribution"]
URL_COLS = ["url", "host", "score", "verdict"]
FEAT_COLS = ["feature", "value", "typical benign", "effect on score", "what it measures"]
COLORS = ["#1a7f37", "#9a6700", "#c62828"]


# ---------------------------------------------------------------- rendering
def banner_html(r, text_model, url_model):
    unjudged = [l for l in r["links"] if l["level"] is None]
    if r["level"] is None and unjudged:   # nothing the models can score, but there is a link we deliberately did not judge
        kinds = {l["kind"] for l in unjudged}
        head = CANT_VERIFY if kinds == {"shortener"} else CANT_JUDGE if kinds == {"free"} else "Can't judge the link"
        why = {"shortener": "A shortened link hides where it goes, and links are never followed here.",
               "free": "Anyone can publish a site on these platforms, so the domain says nothing about this one."}
        sub = " ".join(why[k] for k in ("shortener", "free") if k in kinds)
        return (f"<div style='background:#57606a;color:#fff;border-radius:10px;padding:14px 18px'>"
                f"<div style='font-size:1.6em;font-weight:700'>{head}</div><div style='font-size:.9em;opacity:.95'>{sub} No message text to score.</div></div>")
    if r["level"] is None:
        return "<p>Paste a message, email or link above, then press <b>Analyse</b>.</p>"
    parts = []
    if r["text_score"] is not None:
        parts.append(f"text score <b>{r['text_score']:.3f}</b> (Suspicious from {r['text_thresholds'][0]:.3f}, Likely scam from {r['text_thresholds'][1]:.3f})")
    else:
        parts.append("no message text to score" + (", link only" if r["links"] else ""))
    if r["top_score"] is not None:
        parts.append(f"link score <b>{r['top_score']:.3f}</b> (flagged from {url_model.t_flag:.3f}, Likely scam from {url_model.t_high:.3f})")
    n = lambda kind, judged: sum(l["kind"] == kind and (l["level"] is not None) == judged for l in r["links"])
    plural = lambda k, word: f"{k} {word}" + ("s" if k > 1 else "")
    if n("shortener", False):
        parts.append(f"{plural(n('shortener', False), 'shortened link')} can't be verified")
    if n("free", False):
        parts.append(f"{plural(n('free', False), 'free-hosted link')} can't be judged by domain")
    if n("free", True):
        parts.append("a free-hosted link has a brand or scam keyword in its subdomain (counts as Suspicious)")
    both = r["text_level"] is not None and r["url_level"] is not None and min(r["text_level"], r["url_level"]) >= 1
    if r["escalated"]:
        parts.append("raised to Suspicious by the OTP / PIN / CVV rule")
    sub = "; ".join(parts) + ("; both heads flagged it" if both else "")
    unjudged = any(l["level"] is None for l in r["links"])
    caveat = ("This only means no strong warning signs were found" + (" in what could be checked" if unjudged else "") +
              ". It is not a guarantee, so verify through the official app or number.") if r["level"] == 0 else ""
    return (f"<div style='background:{COLORS[r['level']]};color:#fff;border-radius:10px;padding:14px 18px'>"
            f"<div style='font-size:1.6em;font-weight:700'>{LEVELS[r['level']]}</div>"
            f"<div style='font-size:.9em;opacity:.95'>{sub}</div>"
            + (f"<div style='font-size:.9em;margin-top:4px'>{caveat}</div>" if caveat else "") + "</div>")

def flag_html(r):
    """The OTP / PIN / CVV request rule gets its own red box, separate from the tactic tags and from the level."""
    if not r["cred_request"]:
        return ""
    ev = ", ".join(f"&ldquo;{html.escape(h)}&rdquo;" for h in r["cred_request"])
    return ("<div style='border:2px solid #c62828;background:rgba(198,40,40,.14);border-radius:10px;padding:10px 14px'>"
            "<b style='color:#e5484d'>&#9873; Red flag: asks you to send or share an OTP, PIN or CVV</b> "
            f"<span style='opacity:.9'>{ev}</span><div style='font-size:.9em;margin-top:2px'>No bank, government office or delivery service needs "
            "these sent to them by message or call. The verdict is at least Suspicious whatever the scores say.</div></div>")

def tags_html(r):
    chips = []
    for tag, hits in r["tags"].items():
        if hits:
            ev = ", ".join(f"&ldquo;{html.escape(h)}&rdquo;" for h in hits)
            chips.append(f"<span style='border:1px solid rgba(198,40,40,.7);background:rgba(198,40,40,.14);border-radius:999px;padding:4px 12px'>"
                         f"<b>{tag}</b> <span style='opacity:.85;font-size:.9em'>{ev}</span></span>")
        else:
            chips.append(f"<span style='border:1px solid rgba(128,128,128,.4);border-radius:999px;padding:4px 12px;opacity:.55'>{tag}: none found</span>")
    return "<div style='display:flex;flex-wrap:wrap;gap:8px'>" + "".join(chips) + "</div>"

def grams_df(r):
    rows = [(g.replace(" ", "_"), "scam" if c > 0 else "safe", round(c, 3)) for g, c in sorted(r["grams"], key=lambda t: -abs(t[1]))]
    return pd.DataFrame(rows, columns=GRAM_COLS)

def urls_df(r):
    rows = [(l["url"], l["host"], "-" if l["score"] is None else f"{l['score']:.3f}", l["verdict"]) for l in r["links"]]
    return pd.DataFrame(rows, columns=URL_COLS)

def note_md(r):
    """Markdown under the URL table: why a link was or wasn't scored, then the model's reading of the highest-scoring link."""
    parts = []
    if r["breakdown"] is not None:
        parts.append(f"Breakdown for the highest-scoring scored link: `{r['top_url']}`" + "".join(f"\n- {n}" for n in r["notes"]))
    elif r["links"]:
        parts.append("The URL model scored none of these links.")
    else:
        parts.append("No link found in the input.")
    special = [l for l in r["links"] if l["kind"] != "model"]
    if special:
        parts.append("Not scored by the URL model:" + "".join(f"\n- `{l['url']}`: {l['note']}" for l in special))
    if r.get("truncated"):
        parts.append(f"The text head scored the first {MAX_CHARS} characters only.")
    return "\n\n".join(parts)

def run(text, text_model, url_model):
    r = analyse(text, text_model, url_model)
    no_feats = pd.DataFrame(columns=FEAT_COLS)
    if r["level"] is None and not r["links"]:
        msg = "<p>Nothing to score: no readable text or link found.</p>" if (text or "").strip() else banner_html(r, text_model, url_model)
        return msg, "", tags_html(r), grams_df(r), urls_df(r), no_feats, ""
    return (banner_html(r, text_model, url_model), flag_html(r), tags_html(r), grams_df(r), urls_df(r),
            r["breakdown"] if r["breakdown"] is not None else no_feats, note_md(r))


EXAMPLES = [
    ["Dear SBI customer, your account will be blocked within 24 hours. Complete KYC immediately: http://sbi-kyc-verify-now.xyz/login"],
    ["URGENT: This is Mumbai Police cyber crime. A parcel in your name contains illegal items. Stay on the call, do not tell anyone, and transfer Rs 25000 to clear your name."],
    ["HDFC Bank: Rs 3,200 spent on Card ending 4321 at RELIANCE RETAIL on 28-02-26. Avl Lmt: Rs 75,000. Not you? Call the number on the back of your card."],
    ["http://secure-paytm-wallet-update.top/refund"],
]

def build_ui(text_model, url_model):
    with gr.Blocks(title="Scam check (MVP)") as demo:
        gr.Markdown("# Scam check (MVP)\nPaste a message, email or link. Everything runs on this machine; links are read as text and never opened.")
        inp = gr.Textbox(label="Message, email or link", lines=8, placeholder="Paste here...")
        with gr.Row():
            go = gr.Button("Analyse", variant="primary")
            gr.ClearButton(inp, value="Clear")
        banner = gr.HTML()
        flag = gr.HTML()
        gr.Markdown("### Tactic tags\nHand-written word lists (authority, urgency, payment, isolation). They explain the message but do not change the score.")
        tags = gr.HTML()
        gr.Markdown(f"### Top contributing n-grams\nHow much each piece of text moved the score of the **{text_model.name}**.")
        grams = gr.Dataframe(headers=GRAM_COLS, interactive=False, wrap=True)
        gr.Markdown("### Links found\nShortened links can't be verified (the destination is hidden and never fetched). Free-hosting links (pages.dev, vercel.app, github.io ...) get no model verdict.")
        urls = gr.Dataframe(headers=URL_COLS, interactive=False, wrap=True)
        gr.Markdown("### URL feature breakdown\nHost-only model. *Effect on score* is how much the score drops if that feature took a typical benign value instead.")
        note = gr.Markdown()
        feats = gr.Dataframe(headers=FEAT_COLS, interactive=False, wrap=True)
        gr.Examples(EXAMPLES, inp, label="Examples (made-up; none is a real message)")
        gr.Markdown("**Limits.** Baseline models: scores are not calibrated probabilities and the cut-offs were picked on validation data. "
                    "The text model was trained mostly on English. Combining the two heads is a simple placeholder rule. "
                    "A 'No warning signs found' result only means no strong signal was found. See `reports/` for measured performance.")
        outs = [banner, flag, tags, grams, urls, feats, note]
        go.click(lambda t: run(t, text_model, url_model), inp, outs)
    return demo


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7860)
    a = ap.parse_args()
    build_ui(load_text_model(), load_url_model()).launch(server_name=a.host, server_port=a.port, share=False)
