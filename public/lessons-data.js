/* The lessons, in one place.

   These used to live only in public/app-legacy.js, as a const inside a browser
   script, rendered into a panel at /?view=tool&section=education. That meant
   the entire teaching content of the site sat behind a query string: no URL to
   link, nothing for a search engine to index, and no way to read it without
   loading the whole application first. For something meant to be the top of
   the funnel, it was the least reachable thing on the site.

   This file is the single source. It is loaded as a plain script in the
   browser (window.IL_LESSONS) and required by the server to render the pages
   at /learn, so the in-app panel and the public articles cannot drift apart.
   Adding a lesson means adding an entry here and nothing else. */
(function (root, factory) {
  var data = factory();
  if (typeof module === "object" && module.exports) module.exports = data;
  else root.IL_LESSONS = data;
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  var LESSONS = [
    {
      slug: "site-tour",
      title: "Use ImpliedLens as one decision workflow",
      group: "Getting started",
      minutes: 4,
      summary: "The research sequence ImpliedLens is built around, and why you do not need every tab for every stock.",
      opening: "Most stock research goes wrong in the same way: you open twelve tabs, read whatever is loudest, and end up with an opinion you cannot reconstruct a week later. A process fixes that — not because it makes you right more often, but because it makes you able to tell, afterwards, why you were wrong.",
      body: "The product is organized around a repeatable sequence. Start with the company and chart, verify the business evidence, test valuation, then record the decision. You do not need to visit every tab for every stock.",
      points: [
        "Research: load a ticker and confirm the company, price, source badges, and as-of dates.",
        "Chart and LensScore: identify trend, key zones, tactical setup, long-term value, confidence, and active caps.",
        "Financials, Metrics, and Earnings: verify the operating evidence behind the score.",
        "Value or Projection: test a range of assumptions; do not treat one model output as truth.",
        "Saved or Planner: record the thesis, risks, failure condition, and review date.",
      ],
      formula: "Workflow = Identify → Verify → Value → Decide → Review",
      example: "If LensValue is high but LensSetup is weak, add the company to Saved with a price zone and review date instead of forcing an entry.",
      warning: "Do not jump from a green score to a trade. Confirm source dates, missing fields, and the evidence that could invalidate the idea.",
      closing: "None of this requires you to visit every tab for every company. The sequence is there so you know what you have skipped. Most decisions die at step two, and that is the point — the cheapest research is the research that stops early.",
      tool: "analyze",
      toolLabel: "Open Research",
    },
    {
      slug: "lens-score",
      title: "Read the two lenses before the combined score",
      group: "Reading the tools",
      minutes: 6,
      summary: "What the 0–10 LensScore measures, why it is two separate lenses, and when the combined number is misleading.",
      opening: "A single number that tells you whether to buy a stock would be worth a great deal of money, and nobody has one. LensScore is not that. It is a summary of evidence the tool has already gathered, arranged so you can see which part is carrying the conclusion — and, more usefully, when the two halves disagree.",
      body: "LensScore is a 0–10 buyability metric, not a prediction. LensValue measures the long-term opportunity; LensSetup measures the current technical entry. The combined score is useful only when you can explain what each lens is saying.",
      points: [
        "LensValue covers business quality, valuation, embedded expectations, and downside risk over roughly 1–3 years.",
        "LensTiming measures entry pressure: 10 means the most favorable buyer-side pressure and 0 means an extended, seller-dominated entry. LensTrend separately measures direction.",
        "LensSetup combines timing, support/resistance location, trend, structure, volume, technical risk, and reversal confirmation over roughly 2–12 weeks.",
        "The combined score weights LensValue 70% and LensSetup 30%, then considers agreement and severe risks.",
        "Confidence reports evidence coverage. A cap means one attractive feature—such as oversold momentum or a lower price—cannot erase a falling knife, weak quality, leverage, or missing evidence.",
      ],
      formula: "LensScore = 70% LensValue + 30% LensSetup ± alignment, subject to caps",
      example: "A 9.1 LensValue and 5.0 LensSetup can describe an attractive business at a technically weak entry. Use each lens independently.",
      warning: "Golden Lens is deliberately rare. It requires both lenses to be exceptional, adequate confidence, and no active quality cap.",
      closing: "The habit worth building: read the two lenses first, then the combined score. If you cannot say in one sentence what each lens is telling you, the combined number is not information — it is just a colour.",
      tool: "lens-score",
      toolLabel: "Open LensScore",
    },
    {
      slug: "charts",
      title: "Use technical indicators as a system, not isolated signals",
      group: "Reading the tools",
      minutes: 6,
      summary: "How to read trend, structure, momentum, volume and volatility together instead of hunting for single signals.",
      opening: "Technical analysis has a reputation problem, most of it earned by people treating indicators as predictions. Used properly it is descriptive rather than predictive: it tells you what price has been doing, where it has reacted before, and how much it moves on an average day. That is genuinely useful information, and it is not the same as a forecast.",
      body: "Technical analysis describes price behavior and risk. Start with trend and price structure, then use momentum, volume, and volatility to confirm or challenge that reading.",
      points: [
        "Support and resistance are zones created from repeated price reactions, not exact promises.",
        "The 20-, 50-, and 200-day moving averages describe short-, intermediate-, and long-term trend structure.",
        "RSI and Stochastic RSI describe momentum location; extreme readings can persist in strong trends.",
        "MACD describes changes in trend momentum. Confirm crossovers with price structure and volume.",
        "ATR/price and drawdown describe risk. Use them to size expectations and avoid treating all charts as equally stable.",
      ],
      formula: "Technical case = Structure + Trend + Momentum + Volume − Volatility risk",
      example: "A support retest is stronger when the long-term trend is positive, selling volume fades, and momentum begins improving.",
      warning: "One oversold reading is not a floor. A broken trend with heavy volume can keep falling through prior support.",
      closing: "The discipline is to read them in order — structure, then trend, then momentum, then volume — and to notice when they disagree. Disagreement is information. A single indicator in isolation almost never is.",
      tool: "analyze",
      toolLabel: "Open the chart",
    },
    {
      slug: "financials",
      title: "Separate company facts from valuation assumptions",
      group: "Reading the tools",
      minutes: 7,
      summary: "Separating what a company reported from what you are assuming, and the ratios worth checking before anything else.",
      opening: "Financial statements are the only part of stock research that is not an opinion. Everything else — the valuation, the projection, the price target — is an assumption wearing a number. Keeping those two categories apart is most of what separates research from storytelling.",
      body: "Financial analysis is most useful when every number has a clear status. ImpliedLens distinguishes observed provider data, derived calculations, modeled estimates, and user scenarios.",
      points: [
        "Observed: revenue, net income, cash flow, balance-sheet values, price, and reported earnings from named sources.",
        "Derived: growth rates, margins, ROIC, leverage, dilution, and multiples calculated from observed inputs.",
        "Modeled: fair multiples, value ranges, and expectations gaps produced by disclosed ImpliedLens assumptions.",
        "Scenario: your changed price, growth, margin, or discount-rate inputs; it never replaces reported history.",
        "Always read the source badge, as-of date, EPS basis, unavailable-field message, and sensitivity before acting.",
      ],
      formula: "Per-share value = Business economics × defensible assumptions ÷ diluted shares",
      example: "If annual EPS is stale but four newer reported quarters are complete, the valuation can use disclosed trailing-four-quarter actual EPS instead.",
      warning: "Revenue growth without cash flow, returns on capital, balance-sheet context, and dilution can create a misleading quality impression.",
      closing: "Everything on this site that comes from a filing is labelled with its source and the date it was pulled. When a figure is modelled rather than reported, it says so. That distinction is worth more than any single ratio.",
      tool: "financials",
      toolLabel: "Open Financials",
    },
    {
      slug: "thesis",
      title: "Build a falsifiable stock thesis",
      group: "Making a decision",
      minutes: 5,
      summary: "Writing down what you believe, what would prove you wrong, and when you will check — before you buy.",
      opening: "The hardest part of investing is not finding ideas. It is remembering, eighteen months later, what you actually believed when you bought — and being honest about whether it happened. Memory is generous to itself. Writing is not.",
      body: "A useful stock thesis states what the market may be missing, identifies the operating evidence that should close the gap, and defines what would prove the idea wrong. It is a testable decision record, not a prediction that the price will rise.",
      points: [
        "Variant view: state what you believe differently from the market.",
        "Business driver: connect the view to revenue, margins, cash flow, or per-share value.",
        "Evidence: name the result or catalyst that would support the view.",
        "Failure condition: write the measurable fact that would invalidate it.",
      ],
      formula: "Thesis = Variant view + Business driver + Evidence + Failure condition",
      example: "Example: recurring-revenue mix lifts operating margin faster than expected over the next four quarters.",
      warning: "“The stock looks cheap” is not a thesis unless you explain why earnings or cash-flow expectations are wrong.",
      closing: "A thesis you cannot falsify is not a thesis, it is a hope. The failure condition is the most valuable line in the whole document, and it is the one people most often leave out.",
      tool: "analyze",
      toolLabel: "Choose a stock to research",
    },
  ];

  var BY_SLUG = {};
  LESSONS.forEach(function (l) { BY_SLUG[l.slug] = l; });

  return { lessons: LESSONS, bySlug: BY_SLUG };
});
