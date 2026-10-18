// The risk meter's fixed copy and geometry (D24). The number itself comes from Report.risk_score; the band edges below are the backend's
// (src/shield/core/risk.py BANDS: No warning signs 0-29, Suspicious 30-69, Likely scam 70-100) and are only drawn here.
export const EDGES = [30, 70] as const;   // where Suspicious and Likely scam begin
export const METER_NOTE = "Higher = more warning signs. Not a percentage chance.";

export function bandOf(score: number): { name: string } {
  return { name: score < EDGES[0] ? "no warning signs" : score < EDGES[1] ? "suspicious" : "likely scam" };
}
