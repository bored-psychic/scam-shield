import { describe, expect, test } from "vitest";
import { COMET_MS, CONE_DEG, HOLE_MS, boxSide, clipInside, clipOutside, cometShape, holeShape, toScreen, type Pt } from "./themeSwitch";

// npm test. The theme switch's geometry (lib/themeSwitch.ts, approved prototype docs/design/theme-switch.html): W1 the approved values,
// W2 clip polygons are cut to the screen, W3 the comet's bow shock, W4 the black hole's lit area, W5 the clip paths of the page's layers, W6 which side of the edge a box is on (the glass panes, the globe's second pass). The browser side (durations, frames, the edge
// through the globe, smoothness, interruptions) is e2e/switch.mjs; reduced motion and the end state are e2e/theme.mjs T5.
const W = 1280, H = 800;
const deg = (rad: number) => rad * 180 / Math.PI;
function inside(p: Pt, poly: Pt[]) {
  let c = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++)
    if ((poly[i][1] > p[1]) !== (poly[j][1] > p[1]) && p[0] < (poly[j][0] - poly[i][0]) * (p[1] - poly[i][1]) / (poly[j][1] - poly[i][1]) + poly[i][0]) c = !c;
  return c;
}
const corners: Pt[] = [[1, 1], [W - 1, 1], [1, H - 1], [W - 1, H - 1]];

describe("W1 the approved values", () => {
  test("comet 2.4 s with a 34 degree cone, black hole 2.6 s", () => {
    expect([COMET_MS, CONE_DEG, HOLE_MS]).toEqual([2400, 34, 2600]);
  });
});

describe("W2 toScreen", () => {
  test("leaves a polygon on the screen as it is", () => {
    const p: Pt[] = [[10, 10], [300, 40], [200, 500]];
    expect(toScreen(p, W, H)).toEqual(p);
  });
  test("cuts a huge one to the screen plus 20 px, still covering it", () => {
    const cut = toScreen([[-9000, -9000], [9000, -9000], [9000, 9000], [-9000, 9000]], W, H);
    for (const [x, y] of cut) { expect(x).toBeGreaterThanOrEqual(-20); expect(x).toBeLessThanOrEqual(W + 20); expect(y).toBeGreaterThanOrEqual(-20); expect(y).toBeLessThanOrEqual(H + 20); }
    for (const c of corners) expect(inside(c, cut)).toBe(true);
  });
  test("drops one that is off the screen", () => {
    expect(toScreen([[-900, -900], [-500, -900], [-500, -500]], W, H)).toEqual([]);
  });
});

describe("W3 the comet's bow shock", () => {
  test("flies from beyond the top-right corner and leaves past the bottom-left one by 80%", () => {
    const [x0, y0] = cometShape(0, W, H).head, [x1, y1] = cometShape(.8, W, H).head;
    expect(x0).toBeGreaterThan(W); expect(y0).toBeLessThan(0);
    expect(x1).toBeLessThan(0); expect(y1).toBeGreaterThan(H);
    expect(cometShape(1, W, H).head).toEqual(cometShape(.8, W, H).head);
  });
  test("opens 34 degrees in total until 60%, its arms follow it far behind the nose", () => {
    for (const t of [.2, .5, .6]) {
      const s = cometShape(t, W, H);
      expect(deg(2 * s.beta)).toBeCloseTo(34, 6);
      // the arms' direction far behind the nose (outline points 30 and 40 of 81 on each side: 2800 and 5000 px out)
      for (const [a, b] of [[s.outline[10], s.outline[0]], [s.outline[70], s.outline[80]]]) {
        const v = [b[0] - a[0], b[1] - a[1]], along = -(v[0] * s.d[0] + v[1] * s.d[1]), across = Math.abs(v[0] * s.n[0] + v[1] * s.n[1]);
        expect(deg(Math.atan2(across, along))).toBeCloseTo(17, 0);
      }
    }
  });
  test("has a rounded nose 16 px ahead of the head", () => {
    const s = cometShape(.5, W, H), nose = s.outline[40];
    expect(Math.hypot(nose[0] - s.head[0], nose[1] - s.head[1])).toBeCloseTo(16, 6);
  });
  test("then opens out to ~88 degrees each side, so the whole screen ends light", () => {
    expect(deg(cometShape(1, W, H).beta)).toBeCloseTo(88, 6);
    const end = toScreen(cometShape(1, W, H).outline, W, H);
    for (const c of corners) expect(inside(c, end)).toBe(true);
    expect(toScreen(cometShape(0, W, H).outline, W, H)).toEqual([]);   // nothing is light before the comet arrives
  });
});

describe("W4 the black hole", () => {
  test("opens at the switch, at least 110 px from the screen edges", () => {
    const right = { left: W - 54, top: 13, width: 34, height: 34 };
    expect(holeShape(W, H, right).P).toEqual([W - 110, 110]);
    expect(holeShape(W, H, { left: 400, top: 300, width: 34, height: 34 }).P).toEqual([417, 317]);
  });
  test("the lit radius is the farthest corner (+40 px) x (1 - k^3), gone from 82%", () => {
    const s = holeShape(W, H, null), far = Math.hypot(W - 110, H - 110) + 40;
    expect(s.far).toBeCloseTo(far, 6);
    expect(s.radius(0)).toBeCloseTo(far, 6);
    expect(s.radius(.1)).toBeCloseTo(far, 6);
    const k = (.5 - .1) / .72;
    expect(s.radius(.5)).toBeCloseTo(far * (1 - k ** 3), 6);
    expect(s.radius(.82)).toBe(0);
    expect(s.radius(1)).toBe(0);
    let last = Infinity;
    for (let t = 0; t <= 1; t += .01) { expect(s.radius(t)).toBeLessThanOrEqual(last); last = s.radius(t); }
  });
  test("its edge wobbles by the prototype's edgeR()", () => {
    const s = holeShape(W, H, null);
    expect(s.edgeR(100, 0, 0)).toBeCloseTo(100, 6);
    expect(s.edgeR(100, Math.PI / 6, 0)).toBeCloseTo(100 * (1 + .14 + .07 * Math.sin(5 * Math.PI / 6)), 6);
    expect(s.lit(.5)).toHaveLength(96);
  });
});

describe("W5 the layers' clip paths", () => {
  const tri: Pt[] = [[100, 100], [400, 100], [250, 300]];
  const parse = (css: string): Pt[] => [...css.matchAll(/(-?[\d.]+)px (-?[\d.]+)px/g)].map((m) => [+m[1], +m[2]]);
  test("inside: the polygon, offset to the layer's own box; nothing for an empty one", () => {
    expect(clipInside(tri)).toBe("polygon(100.00px 100.00px,400.00px 100.00px,250.00px 300.00px)");
    expect(parse(clipInside(tri, 8, 64.5))).toEqual([[92, 35.5], [392, 35.5], [242, 235.5]]);
    expect(clipInside([])).toBe("polygon(0 0, 0 0, 0 0)");
  });
  test("outside: the rest of the screen, as an even-odd polygon with the polygon as its hole", () => {
    const css = clipOutside(tri, W, H), ring = parse(css);
    expect(css.startsWith("polygon(evenodd, ")).toBe(true);
    expect(inside([250, 150], ring)).toBe(false);   // inside the polygon: not in the outside clip
    for (const c of [...corners, [600, 600] as Pt, [250, 320] as Pt]) expect(inside(c, ring)).toBe(true);
    const off = parse(clipOutside(tri, W, H, 10, 20));   // offset like every other point
    expect(off[0]).toEqual([-30, -40]);
    expect(off[5]).toEqual([90, 80]);
  });
  test("outside an empty polygon is the whole screen", () => {
    const ring = parse(clipOutside([], W, H));
    expect(ring).toEqual([[-20, -20], [W + 20, -20], [W + 20, H + 20], [-20, H + 20]]);
  });
  test("inside and outside split the screen: every point is in exactly one", () => {
    const shock = toScreen(cometShape(.5, W, H).outline, W, H), a = parse(clipInside(shock)), b = parse(clipOutside(shock, W, H));
    for (let y = 5; y < H; y += 37) for (let x = 5; x < W; x += 41) expect(inside([x, y], a) !== inside([x, y], b)).toBe(true);
  });
});

describe("W6 boxSide", () => {
  const tri: Pt[] = [[0, 0], [1000, 0], [0, 1000]];
  test("no polygon: everything is outside it", () => {
    expect(boxSide([], 10, 10, 50, 50)).toBe("out");
  });
  test("a box well inside, well outside, or with an edge through it", () => {
    expect(boxSide(tri, 100, 100, 200, 200)).toBe("in");
    expect(boxSide(tri, 700, 700, 800, 800)).toBe("out");
    expect(boxSide(tri, 450, 450, 560, 560)).toBe("across");   // the hypotenuse x + y = 1000 runs through it
    expect(boxSide([[300, 300], [320, 300], [310, 320]], 0, 0, 1000, 1000)).toBe("across");   // the whole polygon inside the box
  });
  test("agrees with the pixels: a box is 'in' or 'out' only when all of it is", () => {
    const shock = toScreen(cometShape(.5, W, H).outline, W, H);
    for (let y = 0; y < H; y += 53) for (let x = 0; x < W; x += 67) {
      const side = boxSide(shock, x, y, x + 60, y + 40);
      if (side === "across") continue;
      for (const c of [[x, y], [x + 60, y], [x, y + 40], [x + 60, y + 40], [x + 30, y + 20]] as Pt[]) expect(inside(c, shock)).toBe(side === "in");
    }
  });
});
