"use strict";

const pkg = require("../package.json");

const startedAt = new Date().toISOString();
const commit = process.env.RENDER_GIT_COMMIT || process.env.GIT_COMMIT || "local";
const shortCommit = commit === "local" ? commit : commit.slice(0, 7);

module.exports = {
  app: pkg.name,
  version: pkg.version,
  commit,
  shortCommit,
  environment: process.env.NODE_ENV || "development",
  service: process.env.RENDER_SERVICE_NAME || "implied-lens",
  startedAt,
};
