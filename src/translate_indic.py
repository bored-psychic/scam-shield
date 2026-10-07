import os
os.environ.setdefault("PYTORCH_ENABLE_MPS_FALLBACK", "1")   # an op MPS lacks runs on the CPU instead of failing; each fallback is reported below
import argparse, datetime as dt, glob, json, resource, shutil, sys, time, warnings
import numpy as np, pandas as pd

# English -> Hindi / Kannada with IndicTrans2, on the Mac, in the translate venv (.venv-translate: torch, transformers<5, sentencepiece,
# indictranstoolkit; transformers 5.x breaks both the toolkit import and the model's remote code). Input is the parents file written by
# src/translate_parents.py; spans that must survive verbatim are protected by src/protect.py.
#   .venv-translate/bin/python src/translate_indic.py download [--model 1B|200M]      fetch weights (needs `hf auth login`; gated models)
#   .venv-translate/bin/python src/translate_indic.py run --limit 50 --out <csv> --report reports/translate_timing.md
#                                                                                      the 50-sentence timing test (same code path as the full run)
#   .venv-translate/bin/python src/translate_indic.py run                              all parents -> data/external/indic/translated/
#   ... run --stub                                                                     no model: identity "translation", to test the plumbing
# Output rows carry status "ok" or the reason the row failed (marker_missing / marker_duplicated / stray_marker / empty / copied_source);
# translate_parents.py finalise applies the content filters. The run resumes: rows already in --out are skipped.
MODELS = {"1B": ("ai4bharat/indictrans2-en-indic-1B", "10e65a9951a1e922cd109a95e8aba9357b62144b"),
          "200M": ("ai4bharat/indictrans2-en-indic-dist-200M", "173b94239f7c38886b2747b8d4a5db771a7e1232")}   # revisions pinned: trust_remote_code runs the repo's code
LANGS = {"hindi": "hin_Deva", "kannada": "kan_Knda"}
OUT_DIR = "data/external/indic/translated"
GEN = dict(use_cache=True, min_length=0, max_length=256, num_beams=5, num_return_sequences=1)   # the model card's settings
TODAY = dt.date.today().isoformat()

def gb(x):
    return x / 2 ** 30

def cmd_download(args):
    from huggingface_hub import snapshot_download
    repo, rev = MODELS[args.model]
    t0 = time.time()
    path = snapshot_download(repo, revision=rev, ignore_patterns=["*.bin"])   # the repo ships the weights twice (safetensors + pytorch_model.bin); take one
    secs = time.time() - t0
    size = sum(os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(path) for f in fs)   # symlinks resolve to the blobs
    os.makedirs(OUT_DIR, exist_ok=True)
    info = {"model": args.model, "repo": repo, "revision": rev, "path": path, "bytes": size, "seconds": round(secs, 1), "note": "seconds is 0-ish if the files were already cached"}
    json.dump(info, open(f"{OUT_DIR}/download_{args.model}.json", "w"), indent=1)
    print(f"{repo}@{rev[:8]}: {gb(size):.2f} GB in {secs:.0f} s -> {path}")

class Translator:
    """Protect -> IndicProcessor.preprocess_batch -> model.generate -> postprocess_batch -> restore. Loads the model on MPS in fp16 and falls back to CPU
    fp32 if MPS errors (also reported). stub=True skips the model: the 'translation' is the preprocessed text itself, to test everything around it."""
    def __init__(self, key, device="auto", stub=False):
        from IndicTransToolkit import IndicProcessor
        self.ip, self.stub, self.key = IndicProcessor(inference=True), stub, key
        self.stats = {"model": key, "stub": stub, "fallback_reason": "", "mps_op_fallbacks": [], "mps_peak_driver_gb": 0.0, "mps_peak_current_gb": 0.0}
        if stub:
            self.device, self.dtype, self.stats["load_seconds"], self.stats["warmup_seconds"] = "stub", "none", 0.0, 0.0
            return
        import torch
        self.torch = torch
        want_mps = device in ("auto", "mps") and torch.backends.mps.is_available()
        t0 = time.time()
        self._load("mps" if want_mps else "cpu")
        self.stats["load_seconds"] = round(time.time() - t0, 1)
        t0 = time.time()
        try:
            self._run(self._pre(["Your <ID51> for <ID52> is <ID53>."], "hin_Deva"))   # first call: MPS compiles kernels; reported separately from the steady state
        except Exception as e:
            if self.device != "mps":
                raise
            self.stats["fallback_reason"] = f"{type(e).__name__}: {str(e)[:300]}"
            print("MPS failed, reloading on CPU fp32:", self.stats["fallback_reason"], file=sys.stderr)
            self._load("cpu")
            self._run(self._pre(["Your <ID51> for <ID52> is <ID53>."], "hin_Deva"))
        self.stats["warmup_seconds"] = round(time.time() - t0, 1)

    def _load(self, device):
        from transformers import AutoModelForSeq2SeqLM, AutoTokenizer
        torch = self.torch
        repo, rev = MODELS[self.key]
        self.dtype = torch.float16 if device == "mps" else torch.float32
        self.tok = AutoTokenizer.from_pretrained(repo, revision=rev, trust_remote_code=True)
        try:
            model = AutoModelForSeq2SeqLM.from_pretrained(repo, revision=rev, trust_remote_code=True, dtype=self.dtype)
        except TypeError:   # older transformers spell it torch_dtype
            model = AutoModelForSeq2SeqLM.from_pretrained(repo, revision=rev, trust_remote_code=True, torch_dtype=self.dtype)
        self.model, self.device = model.to(device).eval(), device
        self.stats.update(device=device, dtype=str(self.dtype).replace("torch.", ""), revision=rev)

    def _pre(self, protected, lang):
        return self.ip.preprocess_batch(protected, src_lang="eng_Latn", tgt_lang=lang)

    def _run(self, pre):
        """Model input strings (with language tags) -> decoded strings."""
        if self.stub:
            return [p.split(" ", 2)[2] for p in pre]
        torch = self.torch
        inputs = self.tok(pre, truncation=True, padding="longest", return_tensors="pt", return_attention_mask=True).to(self.device)
        with torch.inference_mode(), warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            out = self.model.generate(**inputs, **GEN)
            if self.device == "mps":
                torch.mps.synchronize()
        for x in w:
            if "MPS" in str(x.message) and str(x.message)[:140] not in self.stats["mps_op_fallbacks"]:
                self.stats["mps_op_fallbacks"].append(str(x.message)[:140])
        if self.device == "mps":
            self.stats["mps_peak_driver_gb"] = max(self.stats["mps_peak_driver_gb"], gb(torch.mps.driver_allocated_memory()))
            self.stats["mps_peak_current_gb"] = max(self.stats["mps_peak_current_gb"], gb(torch.mps.current_allocated_memory()))
        return self.tok.batch_decode(out, skip_special_tokens=True, clean_up_tokenization_spaces=True)

    def translate(self, protected, lang):
        """-> (list of toolkit-postprocessed strings with our markers still in, seconds for model + pre/post)."""
        t0 = time.time()
        post = self.ip.postprocess_batch(self._run(self._pre(protected, lang)), lang=lang)
        return post, time.time() - t0

def run_status(raw, spans, source):
    import protect
    if not raw.strip():
        return "", "empty"
    text, status = protect.restore(raw, spans)
    if status != "ok":
        return "", status
    if text.strip() == source.strip():
        return text, "copied_source"   # came back untranslated
    return text, "ok"

def cmd_run(args):
    import protect
    pf = args.parents or sorted(glob.glob("data/external/indic/translate_in/parents_*.csv"))[-1]
    par = pd.read_csv(pf)
    n_all = len(par)
    if args.limit:
        par = par.sample(n=min(args.limit, len(par)), random_state=args.seed)
    par = par.sort_values("parent_id").reset_index(drop=True)
    prot = [protect.protect(t) for t in par["text"]]
    par["protected"], par["spans"] = [p for p, _ in prot], [s for _, s in prot]
    out = args.out or f"{OUT_DIR}/translated_raw_{TODAY}.csv"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    done = set()
    if os.path.exists(out):
        d = pd.read_csv(out)
        done = set(zip(d["parent_id"], d["lang"]))
        print(f"resuming: {len(done)} (parent, language) rows already in {out}")
    tr = Translator(args.model, args.device, args.stub)
    print(f"{args.model}: device {tr.device}, dtype {tr.dtype}, load {tr.stats['load_seconds']} s, warm-up {tr.stats['warmup_seconds']} s", flush=True)
    t_start, rows, batch_log = time.time(), [], []
    for lang_name, lang in LANGS.items():
        todo = par[[(pid, lang_name) not in done for pid in par["parent_id"]]]
        todo = todo.iloc[todo["protected"].str.len().argsort()]   # similar lengths together: less padding
        for bi, i in enumerate(range(0, len(todo), args.batch)):
            chunk = todo.iloc[i:i + args.batch]
            post, secs = tr.translate(list(chunk["protected"]), lang)
            batch_log.append({"lang": lang_name, "batch": bi, "n": len(chunk), "seconds": secs})
            new = []
            for (_, r), raw in zip(chunk.iterrows(), post):
                text, status = run_status(raw, r["spans"], r["text"])
                new.append({"parent_id": r["parent_id"], "parent_hash": r["parent_hash"], "lang": lang_name, "label": r["label"], "parent_source": r["parent_source"],
                            "protected": r["protected"], "raw_output": raw, "translation": text, "status": status, "batch_seconds": round(secs, 2), "model": args.model,
                            "device": tr.device, "dtype": tr.dtype})
            pd.DataFrame(new).to_csv(out, mode="a", header=not os.path.exists(out), index=False)
            rows += new
            print(f"  {lang_name} batch {bi}: {len(chunk)} sentences in {secs:.1f} s ({secs / len(chunk):.2f} s/sentence); {sum(x['status'] == 'ok' for x in new)} ok", flush=True)
    total = time.time() - t_start
    if args.report:
        write_report(args, tr, par, n_all, rows, batch_log, total, out)
    print(f"wrote {out}")

def write_report(args, tr, par, n_all, rows, batch_log, total, out):
    res = pd.DataFrame(rows)
    bl = pd.DataFrame(batch_log)
    dl = f"{OUT_DIR}/download_{args.model}.json"
    dl = json.load(open(dl)) if os.path.exists(dl) else None
    peak_rss = gb(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)   # bytes on macOS
    n_sent = len(par)
    per_lang = bl.groupby("lang").apply(lambda g: pd.Series({"batches": len(g), "sentences": int(g["n"].sum()), "seconds": g["seconds"].sum(),
                                                             "s_per_sentence": g["seconds"].sum() / g["n"].sum(), "first_batch_s": g["seconds"].iloc[0],
                                                             "median_batch_s": g["seconds"].median()}), include_groups=False)
    s_per = bl["seconds"].sum() / bl["n"].sum()
    full = n_all * len(LANGS) * s_per
    ok = res.groupby("lang")["status"].apply(lambda s: (s == "ok").mean())
    stat = res.groupby(["lang", "status"]).size().unstack(fill_value=0)
    L = [f"# Translation timing test ({args.model}, {tr.device}, {tr.dtype})\n",
         f"Generated by `src/translate_indic.py run --limit {args.limit}` on {TODAY}. {n_sent} sentences sampled from `{os.path.basename(args.parents or 'parents file')}` "
         f"(seed {args.seed}), each translated into Hindi and Kannada, batch size {args.batch}, beam 5, max length 256. Output: `{out}`.\n",
         "## Numbers\n",
         f"- download: " + (f"{gb(dl['bytes']):.2f} GB, {dl['seconds']:.0f} s (revision {dl['revision'][:8]}; safetensors only, `pytorch_model.bin` skipped)" if dl else "not measured in this run"),
         f"- model load (tokenizer + weights + move to {tr.device}): {tr.stats['load_seconds']} s; first-call warm-up (kernel compile, counted separately): {tr.stats['warmup_seconds']} s",
         f"- translation: {bl['n'].sum()} sentence-translations in {bl['seconds'].sum():.0f} s model+pre/post time = **{s_per:.2f} s per sentence** (wall clock incl. CSV writes {total:.0f} s)",
         f"- peak memory: process RSS {peak_rss:.1f} GB (`ru_maxrss`); MPS driver allocation peak {tr.stats['mps_peak_driver_gb']:.1f} GB, MPS tensors peak {tr.stats['mps_peak_current_gb']:.1f} GB",
         f"- projection for the full set: {n_all} parents x {len(LANGS)} languages = {n_all * len(LANGS)} translations x {s_per:.2f} s = **{full / 3600:.1f} h** "
         f"({full / 60:.0f} min) plus load/warm-up; the 4-5 h limit {'is exceeded: use dist-200M' if full / 3600 > 4.5 else 'is not reached'}",
         f"- MPS fallback to CPU for the whole model: {tr.stats['fallback_reason'] or 'none'}; individual ops that fell back to the CPU: {tr.stats['mps_op_fallbacks'] or 'none'}",
         "\n## Per language\n", pd.DataFrame(per_lang).round(2).reset_index().to_markdown(index=False) if hasattr(pd.DataFrame, "to_markdown") and _has_tabulate() else per_lang.round(2).to_string(),
         "\nRows by status (a failed row is a marker the model dropped, duplicated or invented, an empty output, or an untranslated copy):\n",
         stat.to_string(), "\n" + ", ".join(f"{k}: {v:.0%} ok" for k, v in ok.items()) + " (the scam-share sweep assumed 85% of parents survive)\n"]
    for lang_name in LANGS:
        L.append(f"\n## English to {lang_name.capitalize()}: 5 examples\n")
        r = res[(res["lang"] == lang_name) & (res["status"] == "ok")]
        pick = pd.concat([r[r["label"] == 0].head(3), r[r["label"] == 1].head(2)])
        for _, x in pick.iterrows():
            src = par[par["parent_id"] == x["parent_id"]].iloc[0]
            L += [f"**{x['parent_id']}** ({'scam' if x['label'] else 'benign'}, {x['parent_source']})\n", f"- English: {src['text']}", f"- sent to the model: {x['protected']}",
                  f"- {lang_name}: {x['translation']}\n"]
        bad = res[(res["lang"] == lang_name) & (res["status"] != "ok")].head(2)
        for _, x in bad.iterrows():
            L += [f"*failed row {x['parent_id']} ({x['status']})*: model output was `{x['raw_output']}`\n"]
    os.makedirs(os.path.dirname(args.report), exist_ok=True)
    open(args.report, "w", encoding="utf-8").write("\n".join(L) + "\n")
    print(f"wrote {args.report}")
    print(f"  {s_per:.2f} s/sentence | projection {full / 3600:.2f} h for {n_all * len(LANGS)} translations | peak RSS {peak_rss:.1f} GB | "
          + ", ".join(f"{k} {v:.0%} ok" for k, v in ok.items()))

def _has_tabulate():
    try:
        import tabulate  # noqa: F401
        return True
    except ImportError:
        return False

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("download")
    d.add_argument("--model", choices=MODELS, default="1B")
    r = sub.add_parser("run")
    r.add_argument("--model", choices=MODELS, default="1B")
    r.add_argument("--parents")
    r.add_argument("--out")
    r.add_argument("--limit", type=int, help="translate a random sample of this many parents (timing test)")
    r.add_argument("--seed", type=int, default=0)
    r.add_argument("--batch", type=int, default=10)
    r.add_argument("--device", choices=["auto", "mps", "cpu"], default="auto")
    r.add_argument("--stub", action="store_true", help="no model: identity translation, tests the plumbing")
    r.add_argument("--report", help="write the timing report (markdown) here")
    args = ap.parse_args()
    {"download": cmd_download, "run": cmd_run}[args.cmd](args)
