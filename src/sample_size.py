"""How many real messages does an evaluation need?  (Assumption A3 in docs/plans/data_acquisition.md: "we need thousands".)

    .venv/bin/python src/sample_size.py            # prints the markdown tables quoted in docs/plans/data_acquisition.md

For a rate measured on n messages (recall on the scams of one category, or the false-alarm rate on the genuine messages of one category), the
95% Wilson score interval has half-width
    h(n, p) = z / (1 + z^2/n) * sqrt(p(1-p)/n + z^2/(4 n^2)),   z = 1.96,
and this script finds the smallest n with h <= 0.10 (+-10 points) and h <= 0.15 (+-15 points) for several expected rates p. p = 0.5 is the
worst case: it is the n to plan for before any rate is known. No data is read and nothing is written.

n counts INDEPENDENT messages. Messages of one template (the same scam text with other amounts, the same broker alert with another stock) are
not independent; count template groups (src/intake_real.py groups them the same way), or multiply n by the design effect 1 + (m - 1) * rho
when m messages per group are kept (m = 3, rho = 0.5 doubles n).
"""
import math

Z = 1.96
CATEGORIES = ["investment / trading", "loan", "task / part-time", "KYC / bank", "delivery", "digital arrest"]
SCAM_P = [0.5, 0.7, 0.8, 0.9]      # expected recall on scams
GENUINE_P = [0.5, 0.3, 0.1]        # expected false-alarm rate on genuine messages (probe v1: MuRIL 14/48 = 0.29)
WIDTHS = [0.10, 0.15]


def half_width(n, p, z=Z):
    return z / (1 + z * z / n) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))


def n_needed(p, h, z=Z):
    """Smallest n whose 95% Wilson half-width at rate p is <= h."""
    n = 1
    while half_width(n, p, z) > h:
        n += 1
    return n


def main():
    print("| expected rate p | n for +-10 pts | n for +-15 pts |")
    print("|---|---|---|")
    for p in sorted(set(SCAM_P + GENUINE_P)):
        print(f"| {p:.1f} | {n_needed(p, 0.10)} | {n_needed(p, 0.15)} |")
    w10, w15 = n_needed(0.5, 0.10), n_needed(0.5, 0.15)
    print()
    print(f"Planning value (worst case p = 0.5): {w10} per cell for +-10 points, {w15} for +-15 points.")
    cells = 2 * len(CATEGORIES)
    print(f"{len(CATEGORIES)} categories x (scam, genuine) = {cells} cells: {cells * w10} messages for +-10, {cells * w15} for +-15 "
          f"(independent templates; x2 if 3 per template group are kept at rho 0.5).")
    print()
    print("Check, half-width actually reached at the planning n:")
    for n in (w10, w15):
        print(f"  n = {n}: " + ", ".join(f"p {p:.1f} -> +-{half_width(n, p):.3f}" for p in (0.5, 0.7, 0.9)))


if __name__ == "__main__":
    main()
