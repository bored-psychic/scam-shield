import hashlib, random

import pandas as pd

# splits-v3 D-v3.3 item 3 (docs/plans/splits_v3.md): a synthetic BENIGN UPI collect-request family, behind build_text.py --synth-upi-collect (OFF by default).
# It is built only if POOL-val holds fewer than 10 real collect-request groups (counted at B1; switched on or left off on 1 Nov). Not a script that writes a file:
# build_text.py calls make_family() and the rows join the build as source SOURCE.
#   - label 0 (decided 2026-10-27: a bank's collect-request PIN warning is genuine), is_synthetic True, provenance "illustrative" (CLAUDE.md rule 4): never counts as real.
#   - written fresh in the style of the existing synth_india cells, en / hinglish / hi / kn, N_TEMPLATES templates (each a template_family spanning the four languages),
#     N_PER_TEMPLATE slot-filled variants per language. Several families, not one: G3 counts groups, and a single family is one group.
#   - the Hindi and Kannada lines are plain sentences in the wording of the existing synth_india translations; they have NOT been checked by a native speaker
#     (the same standing as the other synth_india hi / kn rows, BUGS.md).
#   - placement is explicit, not the synth_india cell rule (that rule can give a new cluster in the upi / label-0 cell the test slot, and test membership is frozen, D-v3.2):
#     VAL_FAMILIES of the families go to val (so POOL-val + this family can reach G3's 5 groups), the rest to train; never test. build_text.py drops a family cluster that
#     reaches a splits-v2 test cluster (it would be a near-duplicate of synth_upi_0_7_1) and counts it.
#   - honesty (plan D-v3.3): written knowing the test failure. Its val numbers measure the fix on our own wording, not real-world behaviour.

SOURCE = "synth_upi_collect_v3"
FAMILY_PREFIX = "synth_upi_collect_benign_v3"
N_PER_TEMPLATE = 15
VAL_FAMILIES = 5   # of N_TEMPLATES; the other families are train
SLOTS = {
    "name": ["Rahul", "Priya", "Suresh", "Anjali", "Manjunath", "Kavya", "Imran", "Deepa", "Arjun", "Lakshmi"],
    "amt": ["299", "1,500", "4,999", "12,500", "750", "2,000", "9,999"],
    "bank": ["SBI", "HDFC", "ICICI", "Axis", "Canara", "Kotak"],
    "app": ["Google Pay", "PhonePe", "Paytm", "BHIM"],
    "date": ["12-11-2026", "15-11-2026", "20-11-2026", "30-11-2026"],
    "shop": ["Reliance Fresh", "Big Bazaar", "Apollo Pharmacy", "More Supermarket", "Croma"],
}
# (english, hinglish, hindi, kannada): the same message in the four languages, one template_family each
TEMPLATES = [
    ("{app}: {name} has sent you a collect request for Rs {amt}. Approving it and entering your UPI PIN will DEBIT your account. Decline it if you do not know {name}.",
     "{app}: {name} ne aapko Rs {amt} ki collect request bheji hai. Approve karke UPI PIN daalne par aapke account se paise KATENGE. {name} ko nahi jaante to decline karein.",
     "{app}: {name} ने आपको Rs {amt} की कलेक्ट रिक्वेस्ट भेजी है। अप्रूव करके UPI PIN डालने पर आपके खाते से पैसे कटेंगे। {name} को नहीं जानते तो अस्वीकार करें।",
     "{app}: {name} ಅವರು ನಿಮಗೆ Rs {amt} ಕಲೆಕ್ಟ್ ರಿಕ್ವೆಸ್ಟ್ ಕಳುಹಿಸಿದ್ದಾರೆ. ಅಪ್ರೂವ್ ಮಾಡಿ UPI PIN ಹಾಕಿದರೆ ನಿಮ್ಮ ಖಾತೆಯಿಂದ ಹಣ ಕಡಿತವಾಗುತ್ತದೆ. {name} ಗೊತ್ತಿಲ್ಲದಿದ್ದರೆ ನಿರಾಕರಿಸಿ."),
    ("{bank}: A UPI collect request of Rs {amt} from {name} is waiting for your approval. You pay money when you approve and enter your PIN. Do not approve a request you did not expect.",
     "{bank}: {name} ki Rs {amt} ki UPI collect request aapke approval ka intezaar kar rahi hai. Approve karke PIN daalne par aap paise dete hain. Jo request expected nahi, use approve na karein.",
     "{bank}: {name} की Rs {amt} की UPI कलेक्ट रिक्वेस्ट आपकी मंज़ूरी का इंतज़ार कर रही है। मंज़ूर करके PIN डालने पर आप पैसे देते हैं। जिस रिक्वेस्ट की उम्मीद न हो उसे मंज़ूर न करें।",
     "{bank}: {name} ಅವರ Rs {amt} UPI ಕಲೆಕ್ಟ್ ರಿಕ್ವೆಸ್ಟ್ ನಿಮ್ಮ ಅನುಮೋದನೆಗಾಗಿ ಕಾಯುತ್ತಿದೆ. ಅನುಮೋದಿಸಿ PIN ಹಾಕಿದರೆ ನೀವು ಹಣ ಪಾವತಿಸುತ್ತೀರಿ. ನಿರೀಕ್ಷಿಸದ ರಿಕ್ವೆಸ್ಟ್ ಅನ್ನು ಅನುಮೋದಿಸಬೇಡಿ."),
    ("Payment request: {shop} is asking for Rs {amt} on {app}. Check the amount and the name before you enter your UPI PIN. Entering the PIN sends money out of your account.",
     "Payment request: {shop} {app} par Rs {amt} maang raha hai. UPI PIN daalne se pehle amount aur naam check karein. PIN daalne par aapke account se paise nikalte hain.",
     "भुगतान अनुरोध: {shop} {app} पर Rs {amt} मांग रहा है। UPI PIN डालने से पहले राशि और नाम जांच लें। PIN डालने पर आपके खाते से पैसे निकलते हैं।",
     "ಪಾವತಿ ವಿನಂತಿ: {shop} {app} ನಲ್ಲಿ Rs {amt} ಕೇಳುತ್ತಿದೆ. UPI PIN ಹಾಕುವ ಮೊದಲು ಮೊತ್ತ ಮತ್ತು ಹೆಸರನ್ನು ಪರಿಶೀಲಿಸಿ. PIN ಹಾಕಿದರೆ ನಿಮ್ಮ ಖಾತೆಯಿಂದ ಹಣ ಹೋಗುತ್ತದೆ."),
    ("{app} reminder: you have a pending collect request of Rs {amt} from {name}, received on {date}. It will expire if you do nothing. You do not receive money by entering a PIN.",
     "{app} reminder: {name} ki Rs {amt} ki collect request {date} se pending hai. Kuch na karein to expire ho jayegi. PIN daalne se paise receive nahi hote.",
     "{app} रिमाइंडर: {name} की Rs {amt} की कलेक्ट रिक्वेस्ट {date} से लंबित है। कुछ न करें तो समाप्त हो जाएगी। PIN डालने से पैसे प्राप्त नहीं होते।",
     "{app} ನೆನಪೋಲೆ: {name} ಅವರ Rs {amt} ಕಲೆಕ್ಟ್ ರಿಕ್ವೆಸ್ಟ್ {date} ರಿಂದ ಬಾಕಿಯಿದೆ. ಏನೂ ಮಾಡದಿದ್ದರೆ ಅದು ಮುಕ್ತಾಯವಾಗುತ್ತದೆ. PIN ಹಾಕುವುದರಿಂದ ಹಣ ಬರುವುದಿಲ್ಲ."),
    ("{bank} Alert: Rs {amt} will be debited from your account if you approve the UPI request from {name}. If you did not expect this, reject it in your {app} app.",
     "{bank} Alert: {name} ki UPI request approve karne par aapke account se Rs {amt} debit honge. Ye expected nahi tha to {app} app mein reject karein.",
     "{bank} अलर्ट: {name} की UPI रिक्वेस्ट मंज़ूर करने पर आपके खाते से Rs {amt} डेबिट होंगे। यह अपेक्षित नहीं था तो {app} ऐप में अस्वीकार करें।",
     "{bank} ಎಚ್ಚರಿಕೆ: {name} ಅವರ UPI ರಿಕ್ವೆಸ್ಟ್ ಅನುಮೋದಿಸಿದರೆ ನಿಮ್ಮ ಖಾತೆಯಿಂದ Rs {amt} ಡೆಬಿಟ್ ಆಗುತ್ತದೆ. ಇದನ್ನು ನಿರೀಕ್ಷಿಸಿರಲಿಲ್ಲವೆಂದರೆ {app} ಆ್ಯಪ್‌ನಲ್ಲಿ ತಿರಸ್ಕರಿಸಿ."),
    ("{name} requested Rs {amt} from you on {app} on {date}. To pay, approve the request and enter your UPI PIN. To refuse, tap Decline. Banks never ask you to enter a PIN to receive money.",
     "{name} ne {date} ko {app} par aapse Rs {amt} maange hain. Pay karne ke liye request approve karke UPI PIN daalein. Mana karne ke liye Decline dabayein. Bank paise receive karne ke liye PIN nahi maangta.",
     "{name} ने {date} को {app} पर आपसे Rs {amt} मांगे हैं। भुगतान के लिए अनुरोध मंज़ूर करके UPI PIN डालें। मना करने के लिए अस्वीकार दबाएँ। बैंक पैसे पाने के लिए PIN नहीं मांगता।",
     "{name} ಅವರು {date} ರಂದು {app} ನಲ್ಲಿ ನಿಮ್ಮಿಂದ Rs {amt} ಕೇಳಿದ್ದಾರೆ. ಪಾವತಿಸಲು ವಿನಂತಿಯನ್ನು ಅನುಮೋದಿಸಿ UPI PIN ಹಾಕಿ. ನಿರಾಕರಿಸಲು ತಿರಸ್ಕರಿಸಿ ಒತ್ತಿ. ಹಣ ಪಡೆಯಲು ಬ್ಯಾಂಕ್ PIN ಕೇಳುವುದಿಲ್ಲ."),
    ("{shop} has raised a collect request of Rs {amt} on your {bank} UPI id. This is a payment you make, not money you receive. Approve only if you are at the shop.",
     "{shop} ne aapki {bank} UPI id par Rs {amt} ki collect request raise ki hai. Ye aapka payment hai, paise receive nahi honge. Dukaan par ho tabhi approve karein.",
     "{shop} ने आपकी {bank} UPI आईडी पर Rs {amt} की कलेक्ट रिक्वेस्ट भेजी है। यह आपका भुगतान है, पैसे प्राप्त नहीं होंगे। दुकान पर हों तभी मंज़ूर करें।",
     "{shop} ನಿಮ್ಮ {bank} UPI ಐಡಿಗೆ Rs {amt} ಕಲೆಕ್ಟ್ ರಿಕ್ವೆಸ್ಟ್ ಕಳುಹಿಸಿದೆ. ಇದು ನೀವು ಮಾಡುವ ಪಾವತಿ, ನಿಮಗೆ ಹಣ ಬರುವುದಿಲ್ಲ. ಅಂಗಡಿಯಲ್ಲಿದ್ದರೆ ಮಾತ್ರ ಅನುಮೋದಿಸಿ."),
    ("Careful: a UPI collect request for Rs {amt} came from {name}. A collect request takes money from you. If you do not know {name}, decline it and do not enter your PIN.",
     "Savdhaan: {name} se Rs {amt} ki UPI collect request aayi hai. Collect request aapse paise leti hai. {name} ko nahi jaante to decline karein, PIN na daalein.",
     "सावधान: {name} से Rs {amt} की UPI कलेक्ट रिक्वेस्ट आई है। कलेक्ट रिक्वेस्ट आपसे पैसे लेती है। {name} को नहीं जानते तो अस्वीकार करें, PIN न डालें।",
     "ಎಚ್ಚರಿಕೆ: {name} ಅವರಿಂದ Rs {amt} UPI ಕಲೆಕ್ಟ್ ರಿಕ್ವೆಸ್ಟ್ ಬಂದಿದೆ. ಕಲೆಕ್ಟ್ ರಿಕ್ವೆಸ್ಟ್ ನಿಮ್ಮಿಂದ ಹಣ ತೆಗೆದುಕೊಳ್ಳುತ್ತದೆ. {name} ಗೊತ್ತಿಲ್ಲದಿದ್ದರೆ ನಿರಾಕರಿಸಿ, PIN ಹಾಕಬೇಡಿ."),
]
N_TEMPLATES = len(TEMPLATES)
LANGS = ("english", "hinglish", "hindi", "kannada")


def _fill(template, rng):
    out = template
    for k, vals in SLOTS.items():
        while "{" + k + "}" in out:
            out = out.replace("{" + k + "}", rng.choice(vals), 1)
    return out


def family_name(i):
    return f"{FAMILY_PREFIX}_{i}"


def placement():
    """{template_family: "val" | "train"}: the VAL_FAMILIES families that come first in md5 order go to val, the rest to train. Never test."""
    order = sorted((family_name(i) for i in range(N_TEMPLATES)), key=lambda f: hashlib.md5(f.encode()).hexdigest())
    return {f: ("val" if k < VAL_FAMILIES else "train") for k, f in enumerate(order)}


def make_family():
    """The rows in synth_india.csv's columns (text, label, category, channel, language, template_id, template_family) plus source / provenance / is_synthetic.
    Deterministic: the slot draws are seeded per (family, language)."""
    rows = []
    for i, langs in enumerate(TEMPLATES):
        fam = family_name(i)
        for lang, tpl in zip(LANGS, langs):
            rng = random.Random(f"{fam}|{lang}")
            seen = set()
            for _ in range(N_PER_TEMPLATE * 10):
                s = _fill(tpl, rng)
                if s not in seen:
                    seen.add(s)
                    rows.append({"text": s, "label": 0, "category": "upi", "channel": "sms", "language": lang, "template_id": f"{fam}_{lang}",
                                 "template_family": fam})
                if len(seen) >= N_PER_TEMPLATE:
                    break
    d = pd.DataFrame(rows)
    d["source"], d["is_synthetic"], d["provenance"] = SOURCE, True, "illustrative"
    assert d.groupby("template_family")["language"].nunique().eq(4).all()
    return d
