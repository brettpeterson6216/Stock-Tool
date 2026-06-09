"use strict";

const baseUrl = (process.env.DEPLOY_URL || "https://impliedlens.com").replace(/\/$/, "");
const expected = process.env.EXPECTED_COMMIT || process.argv[2] || "";

async function main() {
  const response = await fetch(`${baseUrl}/healthz`, {
    headers: { "Cache-Control": "no-cache" },
  });
  if (!response.ok) throw new Error(`Health check failed with HTTP ${response.status}`);

  const health = await response.json();
  if (!health.ok || health.database !== "ok") {
    throw new Error(`Unhealthy deployment: ${JSON.stringify(health)}`);
  }
  if (expected && !String(health.commit || "").startsWith(expected)) {
    throw new Error(`Expected commit ${expected}, live deployment reports ${health.commit}`);
  }

  console.log(`Healthy ${health.service} ${health.version} (${health.shortCommit}) at ${baseUrl}`);
}

main().catch(error => {
  console.error(error.message);
  process.exit(1);
});
