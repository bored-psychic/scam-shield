# Known bugs and faults

Open issues only. Delete an entry once it is fixed.

## Blocked

- **Web pages not scraped yet.** `data/sources.csv` has 49 URLs, but `src/scrape_web.py` needs `FIRECRAWL_API_KEY` in the environment and has not run.

## Open

- **`src/extract_scams.py` never run end to end.** Only the masking and substring-check logic has been tested offline; the Claude call, output CSV and per-page counts are unverified.
- **Multi-line blockquotes are dropped.** A message quoted across several lines with a `>` at the start of each line is not an exact substring of the page after whitespace normalization, so the check rejects it.
- **Victim-name masking depends on the model.** Names are masked only if Claude lists them in `victim_names`; any it misses stay in the text. Spot-check `data/extracted/web_scams.csv`.
- **`--local` may silently truncate long pages.** Ollama's default context window is a few thousand tokens and its OpenAI-style endpoint can't raise it per request, so the start of a long article can be cut off without an error. Start the server with a larger window, e.g. `OLLAMA_CONTEXT_LENGTH=32768 ollama serve`.
- **`--local` never run against a real model.** Ollama wasn't running when it was added; it has only been tested against a mock server.
- **Every run re-processes all pages.** `extract_scams.py` re-calls the API for every saved page and overwrites `web_scams.csv`; there is no per-page cache.
- **No dependency file.** `anthropic` (1.11.0) was installed into `.venv` by hand; nothing records it or the other packages (`pandas`, `requests`).
