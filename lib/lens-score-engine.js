"use strict";

// The scoring engine remains browser-compatible for the private lab while this
// server entry point is the canonical production import.
module.exports = require("../labs/lens-score/lens-score-engine");
