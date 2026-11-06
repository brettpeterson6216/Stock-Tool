"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   Industry groups: the finer peer sets inside each sector.

   Sectors are too broad to grade against on their own: Visa sits with
   regional banks, Nvidia with software firms, a water utility with a power
   generator. Their normal margins, multiples and debt differ so much that a
   sector percentile partly measures "what kind of business" rather than "how
   good a business". So a company is graded against its industry group when
   the graded universe holds at least MIN_INDUSTRY_PEERS of them, and against
   its sector otherwise.

   Groups come from the SEC's SIC industry codes (every filer has one),
   gathered into ~50 GICS-like groups. A group is only used when it belongs to
   the same sector the company was placed in, so the hand-pinned sectors in
   lib/sec-fundamentals.js (Alphabet in Communication, Amazon in Consumer
   Discretionary, Visa in Financials) fall back to their sector.
   ═══════════════════════════════════════════════════════════════════════════ */

const MIN_INDUSTRY_PEERS = 15;

/* [key, label, sector, ranges]. First match wins, so narrower codes come first. */
const GROUPS = [
  ["semis", "Semiconductors", "Tech", [[3674, 3674]]],
  ["components", "Electronic components", "Tech", [[3670, 3679]]],
  ["hardware", "Computer hardware", "Tech", [[3570, 3579]]],
  ["commsequip", "Communications equipment", "Tech", [[3660, 3669]]],
  ["instruments", "Electronic instruments", "Tech", [[3810, 3829]]],
  ["software", "Software and IT services", "Tech", [[7370, 7379]]],
  ["electrical", "Electrical equipment", "Tech", [[3600, 3659], [3680, 3699]]],

  ["biotech", "Biotechnology", "Health", [[2836, 2836]]],
  ["pharma", "Pharmaceuticals", "Health", [[2830, 2835]]],
  ["meddevices", "Medical devices", "Health", [[3841, 3851]]],
  ["hcservices", "Health care services", "Health", [[8000, 8099]]],
  ["hcdistrib", "Health care distribution", "Health", [[5047, 5047], [5122, 5122]]],

  ["reits", "REITs", "Real Est.", [[6798, 6798]]],
  ["realestate", "Real estate operators", "Real Est.", [[6500, 6553]]],
  ["banks", "Banks", "Finance", [[6020, 6039]]],
  ["credit", "Consumer finance and payments", "Finance", [[6099, 6199]]],
  ["capmarkets", "Capital markets", "Finance", [[6200, 6299]]],
  ["insurance", "Insurance", "Finance", [[6300, 6411]]],
  ["holding", "Holding companies", "Finance", [[6700, 6799]]],

  ["electric", "Electric utilities", "Utilities", [[4910, 4919], [4930, 4931], [4991, 4991]]],
  ["gasutil", "Gas utilities", "Utilities", [[4920, 4929], [4932, 4932]]],
  ["water", "Water utilities", "Utilities", [[4940, 4949]]],
  ["waste", "Waste and environmental", "Utilities", [[4950, 4990]]],

  ["telecom", "Telecom services", "Comm.", [[4810, 4829]]],
  ["broadcast", "Broadcasting and cable", "Comm.", [[4830, 4899]]],
  ["publishing", "Publishing", "Comm.", [[2710, 2799]]],
  ["film", "Movies and entertainment", "Comm.", [[7800, 7849]]],

  ["eandp", "Oil and gas producers", "Energy", [[1300, 1339]]],
  ["oilservices", "Oilfield services", "Energy", [[1380, 1389]]],
  ["refining", "Refining", "Energy", [[2900, 2999]]],
  ["pipelines", "Pipelines", "Energy", [[4610, 4619]]],
  ["coal", "Coal", "Energy", [[1200, 1241]]],

  ["beverages", "Beverages", "Staples", [[2080, 2089]]],
  ["food", "Food products", "Staples", [[2000, 2079], [2090, 2099]]],
  ["tobacco", "Tobacco", "Staples", [[2100, 2199]]],
  ["household", "Household and personal products", "Staples", [[2840, 2844]]],
  ["staplesretail", "Food and staples retail", "Staples", [[5400, 5499], [5140, 5149], [5180, 5182], [5912, 5912], [5331, 5331]]],

  ["metals", "Metals and mining", "Materials", [[1000, 1099], [1400, 1499], [3300, 3399]]],
  ["chemicals", "Chemicals", "Materials", [[2800, 2829], [2850, 2899]]],
  ["packaging", "Paper, packaging and building materials", "Materials", [[2400, 2499], [2600, 2699], [3200, 3299]]],

  ["autos", "Autos and parts", "Cons.Disc", [[3710, 3716], [3750, 3751]]],
  ["homebuilders", "Homebuilders", "Cons.Disc", [[1520, 1531]]],
  ["apparel", "Apparel and footwear", "Cons.Disc", [[2200, 2399], [3140, 3199]]],
  ["restaurants", "Restaurants", "Cons.Disc", [[5800, 5899]]],
  ["retail", "Retail", "Cons.Disc", [[5200, 5799], [5900, 5999]]],
  ["leisure", "Hotels, travel and leisure", "Cons.Disc", [[7000, 7099], [7900, 7999], [3944, 3944], [3949, 3949]]],

  ["aerospace", "Aerospace and defense", "Industrials", [[3720, 3729], [3760, 3769], [3795, 3795]]],
  ["construction", "Construction and engineering", "Industrials", [[1500, 1799]]],
  ["machinery", "Machinery", "Industrials", [[3500, 3569], [3580, 3599]]],
  ["metalfab", "Metal products", "Industrials", [[3400, 3499]]],
  ["rail", "Railroads", "Industrials", [[4000, 4099]]],
  ["airlines", "Airlines", "Industrials", [[4500, 4599]]],
  ["logistics", "Trucking, shipping and logistics", "Industrials", [[4200, 4499], [4700, 4799]]],
  ["bizservices", "Business services", "Industrials", [[7300, 7369], [7380, 7399], [8700, 8799]]],
  ["distribution", "Wholesale distribution", "Industrials", [[5000, 5099]]],
  ["manufacturing", "Other manufacturing", "Industrials", [[3700, 3799], [3800, 3899], [3900, 3999]]],
];

const BY_KEY = new Map(GROUPS.map(([key, label, sector]) => [key, { key, label, sector }]));

/* Pure: SIC code + the sector the company was placed in → group key or null. */
function groupFor(sic, sector) {
  const s = Number(sic);
  if (!Number.isFinite(s) || s <= 0) return null;
  for (const [key, , sec, ranges] of GROUPS) {
    if (ranges.some(([a, b]) => s >= a && s <= b)) return sec === sector ? key : null;
  }
  return null;
}
function label(key) { return BY_KEY.get(key)?.label || null; }

module.exports = { groupFor, label, GROUPS, MIN_INDUSTRY_PEERS };
