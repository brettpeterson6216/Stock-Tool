"use strict";

const express = require("express");
const { checkAnalysisLimit, normalizeTicker } = require("../lib/plan");
const { buildResearchBundle } = require("../lib/stock-research");
const LensScoreEngine = require("../lib/lens-score-engine");

const router = express.Router();

router.get("/lens-score/:ticker", checkAnalysisLimit, async (req, res) => {
  const ticker = normalizeTicker(req.params.ticker);
  if (!ticker) return res.status(400).json({ error: "Invalid ticker." });

  res.setHeader("Cache-Control", "private, max-age=60");
  try {
    const research = await buildResearchBundle(ticker, { range: "5y", interval: "1d" });
    const score = LensScoreEngine.scoreLens({
      bars: research.market.bars,
      fundamentals: research.fundamentals.values,
      metadata: {
        ticker,
        company: research.company,
        source: research.provenance.sources.map(source => source.name).join(" + "),
        marketAsOf: research.provenance.asOf.market,
        fundamentalsAsOf: research.provenance.asOf.fundamentals,
        synthetic: false,
      },
    });
    return res.json({
      schemaVersion: research.schemaVersion,
      ticker,
      company: research.company,
      score,
      market: research.market,
      fundamentals: research.fundamentals,
      earnings: research.earnings,
      provenance: research.provenance,
    });
  } catch (error) {
    const message = String(error?.message || "Research data unavailable.").slice(0, 240);
    console.error(`[lens-score] ${ticker}:`, message);
    return res.status(/invalid ticker/i.test(message) ? 400 : 503).json({
      ticker,
      status: "not-rated",
      score: null,
      synthetic: false,
      error: message,
      reason: "LensScore does not substitute synthetic market or company data.",
    });
  }
});

module.exports = router;
