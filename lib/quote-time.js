"use strict";
/* Which moment a price belongs to (audit F15).

   A daily bar is stamped with the START of its session (9:30 a.m. ET, which
   is 14:30Z for half the year), but the price on it is the session's close.
   Using the bar stamp as the quote time told readers a closing price was
   captured at the opening bell. So:

     barDate    the trading day the bar covers, in New York (YYYY-MM-DD)
     quoteTime  the provider's own quote time, when it sends one
     asOf       the moment the price is as of: the provider's quote time, or
                for a daily bar the 4:00 p.m. ET close of its day once that
                close has happened (mid-session, the time it was fetched) */
const ET_DATE = new Intl.DateTimeFormat("en-CA", { timeZone: "America/New_York", year: "numeric", month: "2-digit", day: "2-digit" });
const ET_HOUR = new Intl.DateTimeFormat("en-US", { timeZone: "America/New_York", hour: "numeric", hour12: false });

function etDate(ms) { return ET_DATE.format(new Date(ms)); }

/* 4:00 p.m. New York time on a YYYY-MM-DD date, as epoch milliseconds. */
function sessionCloseMs(day) {
  const [y, m, d] = String(day).split("-").map(Number);
  for (const utcHour of [20, 21]) {                       // EDT, then EST
    const ms = Date.UTC(y, m - 1, d, utcHour, 0, 0);
    if (Number(ET_HOUR.format(new Date(ms))) % 24 === 16) return ms;
  }
  return Date.UTC(y, m - 1, d, 21, 0, 0);
}

function quoteTimes({ latestTimestamp, regularMarketTime, interval = "1d", now = Date.now() } = {}) {
  const barMs = Number(latestTimestamp) > 0 ? Number(latestTimestamp) * 1000 : null;
  const quoteMs = Number(regularMarketTime) > 0 ? Number(regularMarketTime) * 1000 : null;
  const barDate = barMs ? etDate(barMs) : null;
  const daily = /^(1d|1wk|1mo|5d)$/.test(String(interval || "1d"));
  let asOfMs = quoteMs;
  if (!asOfMs && barMs) {
    if (daily) {
      const close = sessionCloseMs(barDate);
      asOfMs = close <= now ? close : now;          // mid-session: as of when we fetched it
    } else asOfMs = barMs;
  }
  return {
    barDate,
    quoteTime: quoteMs ? new Date(quoteMs).toISOString() : null,
    asOf: asOfMs ? new Date(asOfMs).toISOString() : null,
  };
}

module.exports = { quoteTimes, sessionCloseMs, etDate };
