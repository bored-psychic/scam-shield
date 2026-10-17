// Screenshot input (D19, part B): the checks made before a screenshot is sent to the local OCR endpoint, and the words the page shows.
// Pure functions, unit-tested (V1, V3). The image itself never passes through here: only its type and size are looked at.

export const IMAGE_TYPES = ["image/png", "image/jpeg", "image/webp"] as const;   // what POST /api/ocr reads (it checks the magic bytes)
export const MAX_IMAGE_BYTES = 8 * 1024 * 1024;   // MAX_BYTES in src/shield/ocr/reader.py

// Plain-words messages. 422 shows the API's own detail instead (fixed texts such as "No text found in the screenshot.").
export const OCR_MESSAGES = {
  type: "Use a PNG, JPG or WEBP screenshot.",                         // 415, or refused here
  size: "This image is too large (max 8 MB).",                         // 413, or refused here (a browser may report a network error instead)
  empty: "This file is empty. Choose a screenshot to check.",          // refused here
  unreadable: "The screenshot couldn't be read.",                      // 422 without a detail
  unavailable: "Screenshot reading isn't set up on this computer yet.", // 503: Tesseract or its language data is missing
  unreachable: "Couldn't reach the checker. Is the API running?",      // no answer: network error, timeout, the dev proxy's error page
  failed: "Reading the screenshot failed.",                            // 500, or an answer this page can't read
} as const;

/** null when the file may be sent, else the message to show (and nothing is uploaded). */
export function validateImage(file: Pick<Blob, "type" | "size">): string | null {
  if (!(IMAGE_TYPES as readonly string[]).includes(file.type)) return OCR_MESSAGES.type;
  if (file.size === 0) return OCR_MESSAGES.empty;
  if (file.size > MAX_IMAGE_BYTES) return OCR_MESSAGES.size;
  return null;
}

/** The notice above the box once the text is in it. OCR misreads the rupee sign (BUGS.md), so it always asks for a check. */
export function ocrNotice(dropped: number): string {
  const base = "Text read from your screenshot. Check it before you press Check, especially amounts (₹) and links.";
  return dropped > 0 ? `${base} Removed ${dropped} line${dropped === 1 ? "" : "s"} like times and dates.` : base;
}

/** The image in a paste, or null. A paste with plain text is a text paste and stays one (Word and Excel also put a picture of the text
 *  on the clipboard); only an image with no text, e.g. a screenshot copied to the clipboard, is read. */
export function pastedImage(data: DataTransfer): File | null {
  if (data.getData("text/plain")) return null;
  return firstFile(data);
}

/** The first file in a drop or paste (one screenshot at a time), or null. */
export function firstFile(data: DataTransfer): File | null {
  if (data.files.length > 0) return data.files[0];
  for (const item of Array.from(data.items)) if (item.kind === "file") return item.getAsFile();
  return null;
}
