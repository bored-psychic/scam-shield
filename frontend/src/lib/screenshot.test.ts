import { afterEach, describe, expect, test, vi } from "vitest";
import { ocr, OcrError } from "../api";
import { MAX_IMAGE_BYTES, OCR_MESSAGES, ocrNotice, pastedImage, validateImage } from "./screenshot";

// npm test. Screenshot input (D19, part B): the checks before an upload, how api.ocr() turns the API's answers into plain words, and the
// notice. fetch is mocked: nothing here talks to the API.
const file = (type: string, size: number) => new File([new Uint8Array(size)], "shot", { type });
const MB = 1024 * 1024;

afterEach(() => vi.unstubAllGlobals());

describe("V1 validateImage()", () => {
  test.each(["image/png", "image/jpeg", "image/webp"])("accepts %s from 1 byte up to exactly 8 MB", (type) => {
    expect(validateImage(file(type, 1))).toBeNull();
    expect(validateImage({ type, size: 3 * MB })).toBeNull();
    expect(validateImage({ type, size: MAX_IMAGE_BYTES })).toBeNull();
  });
  test.each([["gif", "image/gif"], ["pdf", "application/pdf"], ["svg", "image/svg+xml"], ["no type", ""]])("rejects %s", (_, type) => {
    expect(validateImage(file(type, 1000))).toBe(OCR_MESSAGES.type);
  });
  test("rejects 9 MB and 8 MB + 1 byte", () => {
    expect(validateImage({ type: "image/png", size: 9 * MB })).toBe(OCR_MESSAGES.size);
    expect(validateImage({ type: "image/jpeg", size: MAX_IMAGE_BYTES + 1 })).toBe(OCR_MESSAGES.size);
    expect(OCR_MESSAGES.size).toBe("This image is too large (max 8 MB).");
  });
  test("rejects an empty file", () => {
    expect(validateImage(file("image/png", 0))).toBe(OCR_MESSAGES.empty);
  });
});

describe("V2 api.ocr() maps every failure to plain words", () => {
  const answer = (status: number, body?: unknown) =>
    vi.fn(async () => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }));
  const png = () => file("image/png", 2000);
  const failureOf = async (p: Promise<unknown>) => {
    const e = await p.then(() => null, (x: unknown) => x);
    expect(e).toBeInstanceOf(OcrError);
    return (e as OcrError).message;
  };

  test.each([
    [413, { detail: "The screenshot is too large (max 8 MB)." }, "This image is too large (max 8 MB)."],
    [415, { detail: "Only PNG, JPEG or WEBP screenshots can be read." }, "Use a PNG, JPG or WEBP screenshot."],
    [422, { detail: "No text found in the screenshot." }, "No text found in the screenshot."],   // the API's own words
    [422, undefined, OCR_MESSAGES.unreadable],
    [503, { detail: "Screenshot reading is not available: Tesseract is not installed." }, "Screenshot reading isn't set up on this computer yet."],
    [500, { detail: "Reading the screenshot failed." }, "Reading the screenshot failed."],
    [500, undefined, "Couldn't reach the checker. Is the API running?"],   // the Vite proxy's empty 500 when the API is down
  ])("%i %j -> %s", async (status, body, message) => {
    vi.stubGlobal("fetch", answer(status, body));
    expect(await failureOf(ocr(png()))).toBe(message);
  });

  test("network error -> Couldn't reach the checker", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("Failed to fetch"); }));
    expect(await failureOf(ocr(png()))).toBe("Couldn't reach the checker. Is the API running?");
  });

  test("too big or wrong type: refused before any upload", async () => {
    const fetch = answer(200, { text: "x", lines: ["x"], dropped: 0 });
    vi.stubGlobal("fetch", fetch);
    expect(await failureOf(ocr(file("image/png", 9 * MB)))).toBe("This image is too large (max 8 MB).");
    expect(await failureOf(ocr(file("image/gif", 2000)))).toBe("Use a PNG, JPG or WEBP screenshot.");
    expect(fetch).not.toHaveBeenCalled();
  });

  test("success: POST /api/ocr, multipart field 'image' without the file's own name -> {text, lines, dropped}", async () => {
    const fetch = answer(200, { text: "Share the OTP\nsbi-kyc-update.top", lines: ["Share the OTP", "sbi-kyc-update.top"], dropped: 2, ms: 900 });
    vi.stubGlobal("fetch", fetch);
    const r = await ocr(new File([new Uint8Array(2000)], "IMG_2041.png", { type: "image/png" }));
    expect(r).toEqual({ text: "Share the OTP\nsbi-kyc-update.top", lines: ["Share the OTP", "sbi-kyc-update.top"], dropped: 2 });
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/ocr");
    expect(init.method).toBe("POST");
    const sent = (init.body as FormData).get("image") as File;
    expect(sent.size).toBe(2000);
    expect(sent.name).toBe("screenshot");
  });

  test("an answer without text is a failure, not an empty box", async () => {
    vi.stubGlobal("fetch", answer(200, { schema_version: "2" }));
    expect(await failureOf(ocr(png()))).toBe(OCR_MESSAGES.failed);
  });

  test("cancelled by the page (screenshot removed): an abort, not a message to show", async () => {
    vi.stubGlobal("fetch", vi.fn((_: string, init: RequestInit) => new Promise((_res, rej) => {
      init.signal!.addEventListener("abort", () => rej(new DOMException("aborted", "AbortError")));
    })));
    const ctl = new AbortController(), p = ocr(png(), ctl.signal);
    ctl.abort();
    const e = await p.then(() => null, (x: unknown) => x);
    expect(e).not.toBeInstanceOf(OcrError);
  });
});

describe("V3 the notice after a screenshot is read", () => {
  test("asks the user to check amounts (₹) and links before pressing Check", () => {
    const n = ocrNotice(0);
    expect(n).toContain("amounts (₹) and links");
    expect(n).toBe("Text read from your screenshot. Check it before you press Check, especially amounts (₹) and links.");
    expect(n).not.toContain("Removed");
  });
  test("counts the dropped chat lines", () => {
    expect(ocrNotice(3)).toBe(`${ocrNotice(0)} Removed 3 lines like times and dates.`);
    expect(ocrNotice(1)).toContain("Removed 1 line like times and dates.");
    expect(ocrNotice(3)).toContain("amounts (₹) and links");
  });
});

test("V4 a paste with text stays a text paste; an image-only paste is read", () => {
  const img = file("image/png", 10);
  const clip = (text: string, files: File[]) =>
    ({ getData: (t: string) => (t === "text/plain" ? text : ""), files, items: [] }) as unknown as DataTransfer;
  expect(pastedImage(clip("Your KYC is pending", []))).toBeNull();
  expect(pastedImage(clip("Your KYC is pending", [img]))).toBeNull();   // Word / Excel copy text with a picture of it
  expect(pastedImage(clip("", [img]))).toBe(img);
  expect(pastedImage(clip("", []))).toBeNull();
});
