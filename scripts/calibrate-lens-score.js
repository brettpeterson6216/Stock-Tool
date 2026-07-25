"use strict";

const fs = require("fs");
const path = require("path");
const { calibrateSetupSeries } = require("../lib/lens-calibration");
const { loadPriceHistory } = require("../lib/stock-research");
const engine = require("../lib/lens-score-engine");

const DEFAULT_UNIVERSE = [
  "AAPL", "MSFT", "NVDA", "GOOGL", "AMZN", "META",
  "JPM", "UNH", "XOM", "CAT", "COST", "NEE",
  "SPY", "QQQ", "IWM",
];

async function mapWithConcurrency(values, limit, worker) {
  const output = new Array(values.length);
  let cursor = 0;
  async function run() {
    while (cursor < values.length) {
      const index = cursor++;
      try {
        output[index] = await worker(values[index], index);
      } catch (error) {
        output[index] = { error: error.message };
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, values.length) }, run));
  return output;
}

async function main() {
  const requested = process.argv.slice(2).filter(value => !value.startsWith("--"));
  const universe = requested.length ? requested.map(value => value.toUpperCase()) : DEFAULT_UNIVERSE;
  const loaded = await mapWithConcurrency(universe, 4, async ticker => {
    const research = await loadPriceHistory(ticker, { range: "10y", interval: "1d" });
    return { ticker, bars: research.bars, provenance: research.provenance };
  });
  const failures = loaded
    .map((value, index) => value?.error ? { ticker: universe[index], error: value.error } : null)
    .filter(Boolean);
  const seriesByTicker = Object.fromEntries(
    loaded.filter(value => value?.bars).map(value => [value.ticker, value.bars])
  );
  if (!Object.keys(seriesByTicker).length) throw new Error("No historical price series were available.");

  const calibration = calibrateSetupSeries(seriesByTicker, {
    minimumBars: 252,
    sampleEvery: 63,
    horizons: [21, 63],
  });
  const artifact = {
    generatedAt: new Date().toISOString(),
    modelVersion: engine.VERSION,
    status: "preliminary-technical-calibration",
    limitations: [
      "The default universe is a liquid U.S. large-cap and ETF sample, not a survivorship-bias-free total-market dataset.",
      "LensValue and Golden Lens require licensed or reconstructed point-in-time fundamentals and estimates before public performance claims are allowed.",
      "Results are diagnostics, not a promise of future returns.",
    ],
    universe: Object.keys(seriesByTicker),
    failures,
    observations: calibration.observations.length,
    methodology: calibration.methodology,
    summary: calibration.summary,
  };
  const outputPath = path.join(__dirname, "..", "public", "lens-calibration.json");
  fs.writeFileSync(outputPath, JSON.stringify(artifact, null, 2) + "\n", "utf8");
  console.log(`Wrote ${outputPath}`);
  console.log(`Model ${artifact.modelVersion}; ${artifact.observations} no-lookahead observations across ${artifact.universe.length} symbols.`);
  for (const horizon of [21, 63]) {
    const row = artifact.summary[horizon];
    console.log(`${horizon}d correlation=${row.scoreReturnCorrelation?.toFixed(3) ?? "n/a"} high-score avg=${row.highScoreAverageReturn == null ? "n/a" : (row.highScoreAverageReturn * 100).toFixed(2) + "%"} low-score avg=${row.lowScoreAverageReturn == null ? "n/a" : (row.lowScoreAverageReturn * 100).toFixed(2) + "%"}`);
  }
}

main().catch(error => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
