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
      "slug": "what-is-a-stock",
      "title": "What you actually own when you buy a stock",
      "group": "Level 1 · Foundations",
      "level": 1,
      "minutes": 5,
      "summary": "A share is a fractional claim on a real business and its future cash. Everything else in investing follows from that one idea.",
      "opening": "Most people meet the stock market as a list of tickers and colored numbers that go up and down. That framing makes investing feel like guessing. The more useful framing is older and plainer: a share is a small piece of ownership in a business, and over long periods its value follows what that business earns.",
      "body": "When a company is public, its ownership is divided into shares. Owning one gives you a proportional claim on the company's profits, assets and votes. The price moves every second because buyers and sellers disagree about what those future profits are worth today, but the thing being priced is the business.",
      "points": [
        "A share is a claim on future cash: the profits a company keeps, reinvests, or pays out as dividends and buybacks.",
        "Market capitalization = share price × shares outstanding. It is the market's price tag on the whole company.",
        "Shareholders are paid last. Suppliers, employees, lenders and tax come first; you own what is left over.",
        "Prices move on changes in expectations, not just on results. A company can report record profits and fall if investors expected more.",
        "Over years, price tends to follow per-share earnings and cash flow. Over weeks, it mostly follows sentiment and flows."
      ],
      "formula": "Market cap = Share price × Shares outstanding",
      "example": "If a company has 1 billion shares at $50, the market values the whole business at $50 billion. If you own 100 shares, you own one ten-millionth of it, and of every dollar it earns.",
      "warning": "A low share price does not mean a stock is cheap. A $5 stock with 20 billion shares is a $100 billion company. Compare companies by market cap and by what they earn, never by price per share.",
      "closing": "Every lesson after this one is a way of answering a single question: what is this business likely to earn, and is the price I am paying reasonable for that? Keep the question in mind and the jargon becomes much easier to place.",
      "tool": "analyze",
      "toolLabel": "Look up a company",
      "tryIt": "Open AAPL. Find the price and the market cap. Divide one by the other to work out roughly how many shares Apple has.",
      "quiz": [
        {
          "q": "Company A trades at $10 a share and Company B at $400. Which is cheaper?",
          "options": [
            "Company A, because the price is lower",
            "Company B, because it is higher quality",
            "You cannot tell from share price alone"
          ],
          "answer": 2,
          "why": "Share price says nothing on its own. You need the number of shares (to get market cap) and what the company earns."
        },
        {
          "q": "In a liquidation, who is paid first?",
          "options": [
            "Shareholders",
            "Lenders and creditors",
            "Whoever bought most recently"
          ],
          "answer": 1,
          "why": "Creditors are paid before owners. Shareholders keep only what is left, which is why equity carries more risk than debt."
        },
        {
          "q": "A company beats last year's profit by 20% and the stock falls. What is the most likely reason?",
          "options": [
            "The market made a mistake",
            "Investors expected even more",
            "Stocks always fall after earnings"
          ],
          "answer": 1,
          "why": "Prices reflect expectations. Good results that miss what was already priced in can still send a stock lower."
        }
      ]
    },
    {
      "slug": "how-markets-work",
      "title": "How a trade happens: exchanges, bid, ask and order types",
      "group": "Level 1 · Foundations",
      "level": 1,
      "minutes": 6,
      "summary": "What happens between pressing buy and owning the share, why there are two prices, and which order type protects you.",
      "opening": "Pressing buy in a brokerage app feels instant, but there is a small market behind that button, and the way you place the order decides what price you actually get. A few minutes on the mechanics saves real money over a lifetime of trades.",
      "body": "Stocks trade on exchanges and other venues where buyers post bids and sellers post asks. The highest bid and lowest ask form the quote. When you buy at market, you pay the ask; when you sell at market, you receive the bid. The gap between them, the spread, is a cost you pay on every round trip.",
      "points": [
        "Bid: the highest price someone will pay right now. Ask: the lowest price someone will sell for. Spread = ask − bid.",
        "Market order: fills immediately at the best available price. Fast, but you do not control the price.",
        "Limit order: fills only at your price or better. You control the price, but it may not fill.",
        "Stop order: becomes a market order once a trigger price trades. Useful for exits, but it can fill well below the stop in a fast move.",
        "Regular US hours are 9:30am to 4:00pm Eastern. Pre-market and after-hours trading is thinner, with wider spreads."
      ],
      "formula": "Round-trip cost ≈ Spread + Commissions + Price impact",
      "example": "A small company is quoted $9.90 bid, $10.10 ask. A market buy fills at $10.10 and an immediate market sell at $9.90: a 2% loss before the stock has moved at all. A limit buy at $10.00 might avoid half of that.",
      "warning": "Market orders on thinly traded stocks, or at the open after big news, can fill far from the last price you saw. Use limit orders whenever the spread is wide or the stock is moving fast.",
      "closing": "None of this decides whether a stock is a good investment. It decides how much of your return you hand away getting in and out. For long-term investors in liquid stocks the cost is small; for frequent traders in small stocks it can be the whole edge.",
      "tool": "analyze",
      "toolLabel": "Check a live quote",
      "tryIt": "Open any stock and look at its average volume. Compare a mega-cap like MSFT with a small company from the screener and notice how much less trades each day.",
      "quiz": [
        {
          "q": "You place a market buy order. Which price do you pay?",
          "options": [
            "The bid",
            "The ask",
            "The last traded price, guaranteed"
          ],
          "answer": 1,
          "why": "Buyers taking liquidity pay the ask. The last trade is just history and is not guaranteed."
        },
        {
          "q": "Which order guarantees your price but not that you get filled?",
          "options": [
            "Market order",
            "Limit order",
            "Stop order"
          ],
          "answer": 1,
          "why": "A limit order only fills at your price or better, so it may never fill."
        },
        {
          "q": "Why are spreads usually wider after hours?",
          "options": [
            "Fewer buyers and sellers are active",
            "Exchanges charge more at night",
            "Prices are not real after 4pm"
          ],
          "answer": 0,
          "why": "Thinner participation means fewer competing quotes, so the gap between bid and ask widens."
        }
      ]
    },
    {
      "slug": "index-funds-first",
      "title": "Index funds, ETFs and the benchmark you have to beat",
      "group": "Level 1 · Foundations",
      "level": 1,
      "minutes": 5,
      "summary": "Why the S&P 500 is the yardstick for every stock pick, and how to decide how much of your money should be picked at all.",
      "opening": "Before choosing individual stocks, it helps to be honest about the alternative. For a few basis points a year, an index fund gives you the whole market. Every stock you pick is a bet that you can do better than that, after costs, taxes and the hours you spend.",
      "body": "An index tracks a defined basket of stocks, such as the 500 large US companies in the S&P 500. Index funds and ETFs hold that basket for you. Because most professional fund managers fail to beat their index over long periods, the index is the bar any stock-picking process has to clear.",
      "points": [
        "The S&P 500 is weighted by market cap: the largest companies move it most.",
        "An ETF trades on an exchange like a stock; a mutual fund is priced once a day. Both can track an index.",
        "Expense ratio is the yearly fee. Broad index funds often charge under 0.10%.",
        "Compare every pick with the index over the same period. A stock up 12% in a year the index rose 25% was a losing decision.",
        "Many investors keep a core in index funds and a smaller satellite portfolio of individual stocks they research."
      ],
      "formula": "Excess return = Your return − Benchmark return",
      "example": "You bought five stocks that returned 9% on average over two years. The S&P 500 returned 24% over the same two years. Your process cost you 15 percentage points compared with doing nothing clever at all.",
      "warning": "Judging picks without a benchmark makes almost any process look good in a rising market. Write down the index level on the day you buy, so you can compare honestly later.",
      "closing": "This is not an argument against picking stocks. It is an argument for picking them deliberately, measuring the results, and sizing the effort to the evidence that it is working.",
      "tool": "analyze",
      "toolLabel": "Compare a stock with SPY",
      "tryIt": "Open SPY, then a stock you like, on the same 1-year range. Which did better, and by how much?",
      "quiz": [
        {
          "q": "Your stock rose 10% this year. The S&P 500 rose 18%. How did the pick do?",
          "options": [
            "It beat the market",
            "It lagged the market by 8 points",
            "It cannot be compared"
          ],
          "answer": 1,
          "why": "Return only means something relative to the alternative you could have owned instead."
        },
        {
          "q": "In a market-cap-weighted index, which company affects the index most?",
          "options": [
            "The one with the highest share price",
            "The one with the largest market cap",
            "Each company equally"
          ],
          "answer": 1,
          "why": "Weights follow total company value, not share price."
        },
        {
          "q": "What is an expense ratio?",
          "options": [
            "The yearly fee a fund charges",
            "A company's cost of sales",
            "The tax on dividends"
          ],
          "answer": 0,
          "why": "It is the annual percentage of your investment the fund keeps to cover its costs."
        }
      ]
    },
    {
      "slug": "risk-and-sizing",
      "title": "Risk, diversification and how much to put in one stock",
      "group": "Level 1 · Foundations",
      "level": 1,
      "minutes": 6,
      "summary": "Position sizing decides whether a bad idea is a lesson or a disaster. How to think about drawdowns, concentration and losses you can survive.",
      "opening": "Good investors are wrong often. What separates them is that being wrong does not knock them out of the game. That is a sizing decision, made before you buy, and it matters more than almost any analysis you will do afterwards.",
      "body": "Risk is the chance of a permanent loss, and the size of that loss if it happens. Diversification spreads that risk across businesses that will not all fail for the same reason. Position sizing caps how much any single mistake can cost you.",
      "points": [
        "Losses compound against you: a 50% fall needs a 100% gain to get back to even.",
        "Drawdown is the fall from a peak. Individual stocks commonly see 30–50% drawdowns even when the business is fine.",
        "Many investors cap a single new position at 2–5% of the portfolio, letting winners grow rather than starting large.",
        "Diversify across industries and risk drivers, not just tickers. Five chip stocks are closer to one bet than five.",
        "Decide your exit conditions before buying: what evidence would make the thesis wrong, and what you will do then."
      ],
      "formula": "Gain needed to recover = 1 ÷ (1 − loss) − 1",
      "example": "With a $20,000 portfolio and a 4% cap, a new position is at most $800. If the company collapses by 60%, the portfolio loses $480, or 2.4%. Painful, but survivable and recoverable.",
      "warning": "Averaging down without new evidence is how small positions become large losses. A lower price only helps if the thesis is still intact.",
      "closing": "Nobody can control whether an investment works. You can control how much it costs you when it does not. Size every position as if you might be wrong, because sometimes you will be.",
      "tool": "advmetrics",
      "toolLabel": "See a stock's risk metrics",
      "tryIt": "Open a stock you own or want, switch to the 5-year chart, and find its largest peak-to-trough fall. Could you hold through that?",
      "quiz": [
        {
          "q": "A stock falls 50%. What gain does it need to get back to where it started?",
          "options": [
            "50%",
            "75%",
            "100%"
          ],
          "answer": 2,
          "why": "Half the money has to double to recover: 1 ÷ (1 − 0.5) − 1 = 100%."
        },
        {
          "q": "Which portfolio is more diversified?",
          "options": [
            "Five semiconductor stocks",
            "Five companies in different industries with different risk drivers",
            "One S&P 500 company with a large weight"
          ],
          "answer": 1,
          "why": "Diversification is about uncorrelated risks, not the number of tickers."
        },
        {
          "q": "When should you decide what would make you sell?",
          "options": [
            "Before buying",
            "After the stock has fallen 30%",
            "Only if the news turns bad"
          ],
          "answer": 0,
          "why": "Exit conditions set in advance are made without the pressure of a loss in front of you."
        }
      ]
    },
    {
      "slug": "income-statement",
      "title": "Read an income statement in ten minutes",
      "group": "Level 2 · Reading a business",
      "level": 2,
      "minutes": 7,
      "summary": "Revenue, gross profit, operating income and EPS: what each line tells you, and the order to read them in.",
      "opening": "An income statement looks like a wall of numbers, but it tells one story from top to bottom: how much the company sold, what it cost to make and sell it, and what was left for owners. Read it top-down and it takes minutes, not hours.",
      "body": "The income statement covers a period, usually a quarter or a year. It starts with revenue and subtracts costs in layers. Each layer, from gross profit to operating income to net income, tells you something different about the business.",
      "points": [
        "Revenue: total sales. Look at growth rate and whether it is speeding up or slowing down.",
        "Gross profit = Revenue − Cost of goods sold. Gross margin shows pricing power and how costly the product is to deliver.",
        "Operating income = Gross profit − Operating expenses (R&D, sales, admin). Operating margin shows how efficiently the whole business runs.",
        "Net income adds interest, taxes and one-off items. It can be distorted by things unrelated to the core business.",
        "EPS (earnings per share) = Net income ÷ Diluted shares. Diluted counts options and convertibles that could become shares."
      ],
      "formula": "Operating margin = Operating income ÷ Revenue",
      "example": "A software company grows revenue 25% with an 80% gross margin and a 5% operating margin. The product is profitable to deliver; the business is spending heavily to grow. Watch whether operating margin rises as growth slows.",
      "warning": "Rising revenue with shrinking margins can mean the company is buying growth with discounts or spending. Read growth and margins together, never one without the other.",
      "closing": "After a few companies you will start reading margins the way a doctor reads vital signs. A sudden change in one is rarely the whole story, but it is almost always worth a question.",
      "tool": "financials",
      "toolLabel": "Open Financials",
      "tryIt": "Open Financials for MSFT and calculate its gross and operating margins for the last two years. Did they rise or fall?",
      "quiz": [
        {
          "q": "Revenue is $100m and cost of goods sold is $40m. What is the gross margin?",
          "options": [
            "40%",
            "60%",
            "100%"
          ],
          "answer": 1,
          "why": "Gross profit is $60m, and $60m ÷ $100m = 60%."
        },
        {
          "q": "Why use diluted rather than basic shares for EPS?",
          "options": [
            "It counts options and convertibles that could become shares",
            "It is always smaller",
            "Regulators ban basic EPS"
          ],
          "answer": 0,
          "why": "Diluted EPS shows earnings per share if potential shares were issued, which is the more conservative view."
        },
        {
          "q": "Revenue grew 30% but operating margin fell from 20% to 8%. What should you ask?",
          "options": [
            "Nothing, growth is what matters",
            "What is the company spending, and is that growth profitable?",
            "Whether the share price went up"
          ],
          "answer": 1,
          "why": "Margin compression alongside growth can mean growth is being bought rather than earned."
        }
      ]
    },
    {
      "slug": "balance-sheet",
      "title": "Read a balance sheet: what it owns and what it owes",
      "group": "Level 2 · Reading a business",
      "level": 2,
      "minutes": 6,
      "summary": "Assets, liabilities and equity at a point in time, and the three checks that flag a fragile company before it is too late.",
      "opening": "The income statement shows a film of the year. The balance sheet is a photograph of one day: everything the company owns, everything it owes, and the difference, which belongs to shareholders. Most companies that fail show it here first.",
      "body": "The balance sheet always balances: assets equal liabilities plus shareholders' equity. You are looking for whether the company could survive a bad year without raising money on bad terms, and whether its assets are as solid as they look.",
      "points": [
        "Assets = Liabilities + Equity, always.",
        "Cash and short-term investments are the cushion. Compare them with debt due in the next year or two.",
        "Net debt = Total debt − Cash. Negative net debt means more cash than borrowing.",
        "Current ratio = Current assets ÷ Current liabilities. Below 1 means bills due within a year exceed liquid assets.",
        "Goodwill and intangibles come from acquisitions. Large goodwill can be written down, cutting equity suddenly."
      ],
      "formula": "Net debt = Total debt − Cash and equivalents",
      "example": "Two companies each earn $1 billion a year. One holds $5 billion of net cash; the other carries $8 billion of net debt maturing in two years. In a recession, the first can buy back stock while the second may have to sell shares at a low price.",
      "warning": "Shareholders' equity is an accounting figure, not market value. A company can have negative equity because of buybacks and still be very healthy, or positive equity built on goodwill that is worth little.",
      "closing": "You do not need to audit the balance sheet. You need to know whether the company controls its own fate. Cash against near-term debt answers that question surprisingly often.",
      "tool": "financials",
      "toolLabel": "Open the balance sheet",
      "tryIt": "Open Financials for a company you know and work out its net debt. Is it negative (net cash) or positive?",
      "quiz": [
        {
          "q": "A company has $3bn of debt and $5bn of cash. What is its net debt?",
          "options": [
            "$8bn",
            "−$2bn (net cash)",
            "$2bn"
          ],
          "answer": 1,
          "why": "Net debt = $3bn − $5bn = −$2bn. More cash than debt."
        },
        {
          "q": "A current ratio of 0.7 means…",
          "options": [
            "Current liabilities exceed current assets",
            "The company is very profitable",
            "The stock is undervalued"
          ],
          "answer": 0,
          "why": "Bills due within a year are larger than the assets convertible to cash within a year."
        },
        {
          "q": "Why can large goodwill be a risk?",
          "options": [
            "It is taxed heavily",
            "It can be written down, reducing equity",
            "It increases debt automatically"
          ],
          "answer": 1,
          "why": "If an acquisition disappoints, the company writes goodwill down, which cuts reported equity and earnings."
        }
      ]
    },
    {
      "slug": "cash-flow",
      "title": "Follow the cash: why profit and cash are different",
      "group": "Level 2 · Reading a business",
      "level": 2,
      "minutes": 6,
      "summary": "Operating cash flow, capital spending and free cash flow, and why the cash flow statement is the hardest one to dress up.",
      "opening": "Profit is an opinion; cash is a fact. That line is a little unfair to accountants, but it captures something real: the income statement depends on estimates and timing choices, while the cash flow statement records money that actually moved.",
      "body": "The cash flow statement reconciles net income with the change in cash. It has three parts: operating activities (the business itself), investing activities (capital spending, acquisitions) and financing activities (debt, buybacks, dividends, share issues).",
      "points": [
        "Operating cash flow (OCF) is cash generated by the business before investment.",
        "Capital expenditure (capex) is spending on equipment, buildings and capitalized software.",
        "Free cash flow (FCF) = OCF − Capex. It is the cash available to repay debt, buy back stock or pay dividends.",
        "Compare FCF with net income over several years. Consistently lower FCF can signal aggressive accounting or heavy reinvestment.",
        "Stock-based compensation is added back to OCF as a non-cash cost, but it dilutes shareholders. Treat it as a real expense."
      ],
      "formula": "Free cash flow = Operating cash flow − Capital expenditure",
      "example": "A retailer reports $500m of net income but only $150m of operating cash flow, because inventory rose by $400m. Either it is preparing for strong demand, or it has stock it cannot sell. The next two quarters will tell you which.",
      "warning": "A company can report growing profits for years while burning cash. If free cash flow never shows up, ask where the earnings are going.",
      "closing": "When the income statement and the cash flow statement disagree, the cash flow statement is usually closer to the truth. Make it the second thing you look at, right after revenue.",
      "tool": "financials",
      "toolLabel": "Open the cash flow statement",
      "tryIt": "For any company, compare net income and free cash flow for the last three years. Which is larger, and is the gap stable?",
      "quiz": [
        {
          "q": "Operating cash flow is $800m and capex is $300m. What is free cash flow?",
          "options": [
            "$1.1bn",
            "$500m",
            "$300m"
          ],
          "answer": 1,
          "why": "FCF = OCF − Capex = $800m − $300m."
        },
        {
          "q": "Net income is rising but operating cash flow is falling. What is a likely cause?",
          "options": [
            "Receivables or inventory are building up",
            "The company paid a dividend",
            "The share price fell"
          ],
          "answer": 0,
          "why": "Working capital growth absorbs cash, so profits are not turning into money in the bank."
        },
        {
          "q": "How should you treat stock-based compensation?",
          "options": [
            "Ignore it, it is non-cash",
            "As a real cost, because it dilutes owners",
            "As revenue"
          ],
          "answer": 1,
          "why": "Paying staff in shares avoids cash outflow but transfers ownership away from existing shareholders."
        }
      ]
    },
    {
      "slug": "quality-ratios",
      "title": "Five ratios that separate great businesses from average ones",
      "group": "Level 2 · Reading a business",
      "level": 2,
      "minutes": 7,
      "summary": "Gross margin, operating margin, return on invested capital, free cash flow conversion and share count: a quick quality screen for any company.",
      "opening": "Professional investors rarely start with valuation. They start by asking whether a business is good, because a great business bought at a fair price usually beats an average business bought cheaply. Five ratios get you most of the way to an answer.",
      "body": "Quality shows up as durable margins, high returns on the money invested in the business, profits that turn into cash, a balance sheet that is not stretched, and a share count that is not quietly growing. Look at each over five years, not one.",
      "points": [
        "Gross margin: high and stable suggests pricing power. Compare with direct competitors, not the whole market.",
        "Operating margin: rising over time shows operating leverage as the company scales.",
        "ROIC (return on invested capital): above roughly 15% for years usually signals a competitive advantage.",
        "FCF conversion = Free cash flow ÷ Net income. Near or above 100% means earnings are real cash.",
        "Diluted share count: falling means buybacks; rising more than 2–3% a year means owners are being diluted."
      ],
      "formula": "ROIC = After-tax operating profit ÷ (Debt + Equity − Cash)",
      "example": "Company A earns a 30% ROIC and grows 8% a year. Company B earns 6% and grows 20%. B's growth may destroy value if its returns are below its cost of capital; A can reinvest every dollar profitably.",
      "warning": "One great year proves little. Margins peak in good economies and in cyclical industries. Always look at a full cycle before calling a business high quality.",
      "closing": "This is a screen, not a verdict. A company that fails it might be fixing itself; one that passes might be about to be disrupted. But it tells you quickly where to spend your research hours.",
      "tool": "advmetrics",
      "toolLabel": "Open Metrics",
      "tryIt": "Pick two competitors, such as KO and PEP, and compare their gross margin, operating margin and share count trend.",
      "quiz": [
        {
          "q": "A company has earned a 25% ROIC for ten years. What does that usually suggest?",
          "options": [
            "A durable competitive advantage",
            "It is about to go bankrupt",
            "Its stock is always cheap"
          ],
          "answer": 0,
          "why": "Persistently high returns on capital mean competitors have not been able to copy what it does."
        },
        {
          "q": "Free cash flow is $40m and net income is $100m. FCF conversion is…",
          "options": [
            "40%",
            "140%",
            "250%"
          ],
          "answer": 0,
          "why": "$40m ÷ $100m = 40%. Most of the reported profit is not arriving as cash."
        },
        {
          "q": "The diluted share count rose 6% a year for five years. What happened to each share's slice of the company?",
          "options": [
            "It grew",
            "It shrank",
            "It stayed the same"
          ],
          "answer": 1,
          "why": "More shares split the same business more ways, so each share owns less."
        }
      ]
    },
    {
      "slug": "financials",
      "title": "Separate reported facts from your assumptions",
      "group": "Level 2 · Reading a business",
      "level": 2,
      "minutes": 7,
      "summary": "Separating what a company reported from what you are assuming, and the ratios worth checking before anything else.",
      "opening": "Financial statements are the only part of stock research that is not an opinion. Everything else — the valuation, the projection, the price target — is an assumption wearing a number. Keeping those two categories apart is most of what separates research from storytelling.",
      "body": "Financial analysis is most useful when every number has a clear status. ImpliedLens distinguishes observed provider data, derived calculations, modeled estimates, and user scenarios.",
      "points": [
        "Observed: revenue, net income, cash flow, balance-sheet values, price, and reported earnings from named sources.",
        "Derived: growth rates, margins, ROIC, leverage, dilution, and multiples calculated from observed inputs.",
        "Modeled: fair multiples, value ranges, and expectations gaps produced by disclosed ImpliedLens assumptions.",
        "Scenario: your changed price, growth, margin, or discount-rate inputs; it never replaces reported history.",
        "Always read the source badge, as-of date, EPS basis, unavailable-field message, and sensitivity before acting."
      ],
      "formula": "Per-share value = Business economics × defensible assumptions ÷ diluted shares",
      "example": "If annual EPS is stale but four newer reported quarters are complete, the valuation can use disclosed trailing-four-quarter actual EPS instead.",
      "warning": "Revenue growth without cash flow, returns on capital, balance-sheet context, and dilution can create a misleading quality impression.",
      "closing": "Everything on this site that comes from a filing is labeled with its source and the date it was pulled. When a figure is modeled rather than reported, it says so. That distinction is worth more than any single ratio.",
      "tool": "financials",
      "toolLabel": "Open Financials",
      "tryIt": "Open Financials for any company and find one reported figure and one figure the site calculated from it. Check the source badge on each.",
      "quiz": [
        {
          "q": "Which of these is a reported fact rather than an assumption?",
          "options": [
            "Next year's revenue growth",
            "Last year's revenue from the 10-K",
            "A fair P/E multiple"
          ],
          "answer": 1,
          "why": "Only figures from filings are reported. Forecasts and fair multiples are assumptions."
        },
        {
          "q": "Revenue is growing but free cash flow and returns on capital are falling. What does this suggest?",
          "options": [
            "Quality is improving",
            "Growth may be getting more expensive",
            "Nothing useful"
          ],
          "answer": 1,
          "why": "Growth without cash or returns can mask a weakening business."
        }
      ]
    },
    {
      "slug": "valuation-multiples",
      "title": "P/E, EV/EBITDA and other multiples, and when they lie",
      "group": "Level 3 · Valuation",
      "level": 3,
      "minutes": 7,
      "summary": "How price multiples work, which one fits which kind of company, and the traps that make a cheap stock expensive.",
      "opening": "Multiples are the fastest way to compare what you pay for different businesses. They are also the most misused number in investing, because a multiple compresses an entire future into one ratio. Knowing what each one hides is as important as knowing how to calculate it.",
      "body": "A multiple divides what you pay by something the company produces: earnings, sales, cash flow. A lower multiple means you pay less for each unit, but only if that unit is as good and will grow as fast. Multiples must always be compared with something: the company's own history, its peers, and its growth.",
      "points": [
        "P/E = Share price ÷ EPS. Forward P/E uses next year's expected EPS; trailing uses the last twelve months.",
        "EV/EBITDA uses enterprise value (market cap + net debt), so it compares companies with different debt levels fairly.",
        "P/S (price to sales) is used for companies that are not yet profitable. It ignores margins entirely.",
        "PEG = P/E ÷ expected growth rate. It adjusts for growth but depends heavily on the growth estimate.",
        "FCF yield = Free cash flow ÷ Market cap. It is the inverse of a cash-based multiple and is easy to compare with bond yields."
      ],
      "formula": "Enterprise value = Market cap + Debt − Cash",
      "example": "Two companies trade at 15× earnings. One has net cash and grows 12% a year; the other has heavy debt and flat sales. They are not equally cheap: on EV/EBITDA, the indebted company is far more expensive.",
      "warning": "A very low P/E often means the market expects earnings to fall, as at the peak of a cycle or before a disruption. Ask why it is cheap before concluding that it is.",
      "closing": "Use multiples to frame questions, not to answer them. If a stock looks cheap, your job is to find the reason the market disagrees and decide whether the market is right.",
      "tool": "dcf",
      "toolLabel": "Open the Valuation Lab",
      "tryIt": "Compare the P/E of NVDA and INTC. Then look at each company's revenue growth. Does the gap in multiples look justified?",
      "quiz": [
        {
          "q": "A $50 stock has $2.50 of EPS. What is its P/E?",
          "options": [
            "12.5",
            "20",
            "125"
          ],
          "answer": 1,
          "why": "$50 ÷ $2.50 = 20."
        },
        {
          "q": "Why compare companies on EV/EBITDA instead of P/E when their debt differs?",
          "options": [
            "EV includes debt, so leverage is accounted for",
            "EBITDA is always larger",
            "P/E is illegal for indebted companies"
          ],
          "answer": 0,
          "why": "Enterprise value prices the whole capital structure, so debt-heavy companies are not flattered."
        },
        {
          "q": "A steel company trades at 5× peak-cycle earnings. What is a key risk?",
          "options": [
            "Earnings may fall sharply as the cycle turns",
            "The P/E is too high",
            "Steel companies cannot be valued"
          ],
          "answer": 0,
          "why": "Cyclical earnings at a peak make a low P/E misleading: the 'E' is about to shrink."
        }
      ]
    },
    {
      "slug": "dcf-basics",
      "title": "Discounted cash flow without the mystique",
      "group": "Level 3 · Valuation",
      "level": 3,
      "minutes": 8,
      "summary": "A business is worth the cash it will produce, discounted back to today. How a DCF works, which inputs matter most, and why the output is a range.",
      "opening": "A discounted cash flow model sounds like something only analysts build. The idea underneath is simple enough to do on a napkin: money in the future is worth less than money today, so you add up the cash a business will produce and shrink each year's amount by how far away it is.",
      "body": "A DCF projects free cash flow for several years, estimates a terminal value for everything after that, and discounts it all at a rate that reflects risk. Dividing the result by diluted shares gives a value per share. The model is only as good as its assumptions, which is why a range of scenarios beats a single number.",
      "points": [
        "Projection period: usually 5–10 years of free cash flow, built from revenue growth and margin assumptions.",
        "Discount rate: the return you require for the risk. Higher rates shrink distant cash flows more.",
        "Terminal value: the value of all cash after the projection. It is often more than half the total, so be conservative.",
        "Equity value = Enterprise value − Net debt. Then divide by diluted shares.",
        "Sensitivity: change growth, margin and discount rate one at a time to see which assumption the value depends on."
      ],
      "formula": "Present value = Future cash ÷ (1 + discount rate)^years",
      "example": "$100 received in 10 years, discounted at 9%, is worth about $42 today. That is why a company promising profits far in the future is so sensitive to interest rates and to its own execution.",
      "warning": "A DCF can justify any price if you tweak the inputs. If a 1-point change in the terminal growth rate moves the value by 40%, the model is telling you how uncertain you are, not what the stock is worth.",
      "closing": "Treat the output as a map of assumptions. The valuable question is not 'what is it worth?' but 'what would I have to believe for today's price to make sense, and do I believe it?'",
      "tool": "dcf",
      "toolLabel": "Build a valuation",
      "tryIt": "In the Valuation Lab, change the discount rate by one percentage point in each direction and note how much the per-share value moves.",
      "quiz": [
        {
          "q": "What happens to a DCF value when the discount rate rises?",
          "options": [
            "It rises",
            "It falls",
            "It does not change"
          ],
          "answer": 1,
          "why": "A higher rate shrinks every future cash flow more, so the present value falls."
        },
        {
          "q": "Why is the terminal value so influential?",
          "options": [
            "It often makes up most of the total value",
            "It is set by regulators",
            "It only covers one year"
          ],
          "answer": 0,
          "why": "It captures all cash flows beyond the forecast, which for a long-lived business is most of the value."
        },
        {
          "q": "What is the best use of a DCF?",
          "options": [
            "To find the one true price",
            "To see which assumptions the value depends on",
            "To predict next quarter's EPS"
          ],
          "answer": 1,
          "why": "Its strength is making assumptions explicit and testable, not producing a precise answer."
        }
      ]
    },
    {
      "slug": "priced-in",
      "title": "Reverse valuation: what is the price already assuming?",
      "group": "Level 3 · Valuation",
      "level": 3,
      "minutes": 6,
      "summary": "Instead of forecasting a target, work backwards from today's price to the growth and margins it requires. This is the core idea behind ImpliedLens.",
      "opening": "Forecasting a company's next ten years is hard, and most forecasts are wrong. There is a more modest question that is often more useful: what does the current price already assume? Answer that, and your job becomes judging whether those assumptions are too high or too low.",
      "body": "Reverse valuation takes the market price as given and solves for the growth, margins or cash flows that would justify it. If the implied expectations look easy to beat, the stock may be attractive. If they require near-perfect execution for a decade, the risk is on the downside even for a great company.",
      "points": [
        "Start with enterprise value and a reasonable discount rate.",
        "Solve for the revenue growth or margin needed to produce that value.",
        "Compare the implied numbers with the company's history and its industry's best performers.",
        "A great business priced for perfection can be a poor investment; a mediocre one priced for collapse can be a good one.",
        "The gap between implied and plausible is your margin of safety, or your risk."
      ],
      "formula": "Expectations gap = Your plausible outcome − Market-implied outcome",
      "example": "A stock's price implies 25% annual revenue growth for ten years with 35% margins. Only a handful of companies in history have done that. You may love the product, but you are betting it joins that tiny group.",
      "warning": "'Priced in' is not the same as 'fairly priced'. Markets can be wrong in both directions for long periods. The point is to know which way you are betting.",
      "closing": "This is the question ImpliedLens is named after. Every tool on the site is built to help you answer it: what does the price imply, and is the business likely to beat it?",
      "tool": "projection",
      "toolLabel": "Open the Projection Lab",
      "tryIt": "In the Projection Lab, adjust the Base case until the modeled value equals today's price. Write down the growth rate you needed. Is it realistic?",
      "quiz": [
        {
          "q": "What does reverse valuation solve for?",
          "options": [
            "The share price next month",
            "The growth and margins today's price implies",
            "The company's tax rate"
          ],
          "answer": 1,
          "why": "It takes the price as given and works out the expectations embedded in it."
        },
        {
          "q": "A great company's price implies growth far above anything it has achieved. What is the risk?",
          "options": [
            "Limited, because it is a great company",
            "Disappointment even if results are good",
            "None, prices always rise for good companies"
          ],
          "answer": 1,
          "why": "If the expectations are extreme, merely good results can still lead to losses."
        },
        {
          "q": "Where does your margin of safety come from in this approach?",
          "options": [
            "The gap between implied and plausible outcomes",
            "A low share price",
            "A high dividend"
          ],
          "answer": 0,
          "why": "The safety is the distance between what the market requires and what you believe is likely."
        }
      ]
    },
    {
      "slug": "trend-support-resistance",
      "title": "Trend, support and resistance: reading a price chart",
      "group": "Level 4 · Charts and timing",
      "level": 4,
      "minutes": 6,
      "summary": "Candles, trends, moving averages and the price zones where buyers and sellers have acted before. The foundation every indicator builds on.",
      "opening": "Fundamental analysis tells you what to own. Charts help with when and how much, and with noticing when the market strongly disagrees with you. You do not need to become a trader to benefit from reading a chart properly.",
      "body": "A chart is a record of where buyers and sellers agreed on price over time. Trends show who has been in control. Support and resistance mark zones where the balance has shifted before. Moving averages smooth the noise so the trend is easier to see.",
      "points": [
        "A candlestick shows open, high, low and close for one period. A long lower wick means buyers stepped in during the period.",
        "Uptrend: higher highs and higher lows. Downtrend: lower highs and lower lows. Anything else is a range.",
        "Support is a zone where falling prices have repeatedly stopped. Resistance is where rising prices have stalled.",
        "The 50-day and 200-day moving averages show intermediate and long-term trend. Price above both, with the 50 above the 200, is a healthy uptrend.",
        "Volume confirms moves. A breakout on heavy volume is more credible than one on light volume."
      ],
      "formula": "Uptrend = Higher highs + Higher lows",
      "example": "A stock pulls back to a zone near $80 where it bounced twice last year, while the 200-day average is rising beneath it. That is a reasonable place to buy with a clear exit: a close well below $80 would break the pattern.",
      "warning": "Support breaks. When a level that held several times finally gives way on heavy volume, it often becomes resistance. Do not keep buying a broken level out of loyalty.",
      "closing": "The goal is not to predict the next candle. It is to avoid buying into obvious downtrends, to place entries near logical levels, and to have a visible line that tells you when you are wrong.",
      "tool": "analyze",
      "toolLabel": "Open the chart",
      "tryIt": "Open any stock on a 1-year chart, turn on the 50-day and 200-day averages, and mark one support and one resistance zone.",
      "quiz": [
        {
          "q": "Which pattern defines an uptrend?",
          "options": [
            "Lower highs and lower lows",
            "Higher highs and higher lows",
            "One big green candle"
          ],
          "answer": 1,
          "why": "An uptrend is a sequence of higher highs and higher lows."
        },
        {
          "q": "A stock breaks below strong support on very heavy volume. What often happens to that level?",
          "options": [
            "It becomes resistance",
            "It disappears from the chart",
            "It guarantees a bounce"
          ],
          "answer": 0,
          "why": "Former support often turns into resistance as trapped buyers sell on the way back up."
        },
        {
          "q": "Why does volume matter on a breakout?",
          "options": [
            "It shows conviction behind the move",
            "It sets the price",
            "It has no meaning"
          ],
          "answer": 0,
          "why": "Heavy volume means many participants agreed with the move, making it more likely to hold."
        }
      ]
    },
    {
      "slug": "charts",
      "title": "Use technical indicators as a system, not isolated signals",
      "group": "Level 4 · Charts and timing",
      "level": 4,
      "minutes": 6,
      "summary": "How to read trend, structure, momentum, volume and volatility together instead of hunting for single signals.",
      "opening": "Technical analysis has a reputation problem, most of it earned by people treating indicators as predictions. Used properly it is descriptive rather than predictive: it tells you what price has been doing, where it has reacted before, and how much it moves on an average day. That is genuinely useful information, and it is not the same as a forecast.",
      "body": "Technical analysis describes price behavior and risk. Start with trend and price structure, then use momentum, volume, and volatility to confirm or challenge that reading.",
      "points": [
        "Support and resistance are zones created from repeated price reactions, not exact promises.",
        "The 20-, 50-, and 200-day moving averages describe short-, intermediate-, and long-term trend structure.",
        "RSI and Stochastic RSI describe momentum location; extreme readings can persist in strong trends.",
        "MACD describes changes in trend momentum. Confirm crossovers with price structure and volume.",
        "ATR/price and drawdown describe risk. Use them to size expectations and avoid treating all charts as equally stable."
      ],
      "formula": "Technical case = Structure + Trend + Momentum + Volume − Volatility risk",
      "example": "A support retest is stronger when the long-term trend is positive, selling volume fades, and momentum begins improving.",
      "warning": "One oversold reading is not a floor. A broken trend with heavy volume can keep falling through prior support.",
      "closing": "The discipline is to read them in order — structure, then trend, then momentum, then volume — and to notice when they disagree. Disagreement is information. A single indicator in isolation almost never is.",
      "tool": "analyze",
      "toolLabel": "Open the chart",
      "tryIt": "Open a stock, turn on RSI and MACD, and find one moment where momentum turned before price did.",
      "quiz": [
        {
          "q": "RSI is above 70 during a strong uptrend. What does that mean on its own?",
          "options": [
            "Sell immediately",
            "Momentum is strong; it can stay high for a long time",
            "The trend has ended"
          ],
          "answer": 1,
          "why": "Overbought readings persist in strong trends. Confirm with structure before acting."
        },
        {
          "q": "In what order does the lesson suggest reading indicators?",
          "options": [
            "Momentum, then volume, then trend",
            "Structure, trend, momentum, volume",
            "Whatever is most extreme first"
          ],
          "answer": 1,
          "why": "Start with the big picture (structure and trend) and use the rest to confirm or challenge it."
        }
      ]
    },
    {
      "slug": "lens-score",
      "title": "Read the two lenses before the combined score",
      "group": "Level 4 · Charts and timing",
      "level": 4,
      "minutes": 6,
      "summary": "What the 0–10 LensScore measures, why it is two separate lenses, and when the combined number is misleading.",
      "opening": "A single number that tells you whether to buy a stock would be worth a great deal of money, and nobody has one. LensScore is not that. It is a summary of evidence the tool has already gathered, arranged so you can see which part is carrying the conclusion — and, more usefully, when the two halves disagree.",
      "body": "LensScore is a 0–10 buyability metric, not a prediction. LensValue measures the long-term opportunity; LensSetup measures the current technical entry. The combined score is useful only when you can explain what each lens is saying.",
      "points": [
        "LensValue covers business quality, valuation, embedded expectations, and downside risk over roughly 1–3 years.",
        "LensTiming measures entry pressure: 10 means the most favorable buyer-side pressure and 0 means an extended, seller-dominated entry. LensTrend separately measures direction.",
        "LensSetup combines timing, support/resistance location, trend, structure, volume, technical risk, and reversal confirmation over roughly 2–12 weeks.",
        "The combined score weights LensValue 70% and LensSetup 30%, then considers agreement and severe risks.",
        "Confidence reports evidence coverage. A cap means one attractive feature—such as oversold momentum or a lower price—cannot erase a falling knife, weak quality, leverage, or missing evidence."
      ],
      "formula": "LensScore = 70% LensValue + 30% LensSetup ± alignment, subject to caps",
      "example": "A 9.1 LensValue and 5.0 LensSetup can describe an attractive business at a technically weak entry. Use each lens independently.",
      "warning": "Golden Lens is deliberately rare. It requires both lenses to be exceptional, adequate confidence, and no active quality cap.",
      "closing": "The habit worth building: read the two lenses first, then the combined score. If you cannot say in one sentence what each lens is telling you, the combined number is not information — it is just a color.",
      "tool": "lens-score",
      "toolLabel": "Open LensScore",
      "tryIt": "Open LensScore for two companies and compare their LensValue and LensSetup separately before looking at the combined score.",
      "quiz": [
        {
          "q": "LensValue is 9 and LensSetup is 4. What is the most sensible reading?",
          "options": [
            "Strong business, weak entry timing",
            "Avoid the stock entirely",
            "Buy immediately"
          ],
          "answer": 0,
          "why": "The lenses measure different things: long-term value is strong while the technical entry is not."
        },
        {
          "q": "What does a cap on the score mean?",
          "options": [
            "The score is maxed out",
            "One severe risk limits how high the score can go",
            "The data is real-time"
          ],
          "answer": 1,
          "why": "Caps stop one attractive feature from hiding a serious problem like a falling knife or weak quality."
        }
      ]
    },
    {
      "slug": "earnings-season",
      "title": "Earnings season: what to read and what to ignore",
      "group": "Level 5 · Making decisions",
      "level": 5,
      "minutes": 6,
      "summary": "How to read a quarterly report, why guidance matters more than the headline beat, and how to update your thesis instead of reacting to the price.",
      "opening": "Four times a year every public company reports results, and for a week the market overreacts to almost all of them. Earnings season is where theses are confirmed or broken, but only if you know which numbers you were waiting for.",
      "body": "A quarterly report includes results against analyst estimates, management's guidance for the coming quarter or year, and commentary on the earnings call. The stock's reaction depends on all three compared with expectations, not on whether results were good in absolute terms.",
      "points": [
        "Beat or miss: actual revenue and EPS against consensus estimates. Small beats are routine; companies guide conservatively.",
        "Guidance: the company's own forecast. A beat with lowered guidance often sends a stock down.",
        "Margins and cash flow: check whether the beat came from the core business or from one-offs and tax.",
        "The call: listen for changes in tone, new risks, and answers that avoid the question.",
        "Your thesis metric: the one number you wrote down in advance. Did it move the way you expected?"
      ],
      "formula": "Reaction ≈ (Results − Expectations) + (New guidance − Old expectations)",
      "example": "A company beats EPS by 5% but cuts full-year revenue guidance, citing slower orders. The stock falls 12%. The quarter was fine; the future just became less certain, and the price reflects the future.",
      "warning": "Do not judge a quarter by the after-hours move. Early reactions are often reversed once investors read the full report and listen to the call.",
      "closing": "Write down before the report what you expect and what would worry you. Afterwards, compare the report with your notes, not with the price. That habit turns earnings season from noise into evidence.",
      "tool": "earnings",
      "toolLabel": "Open Earnings",
      "tryIt": "Open Earnings for a company that reported recently. Did it beat or miss EPS estimates in each of the last four quarters?",
      "quiz": [
        {
          "q": "A company beats EPS estimates but lowers next year's guidance. A common reaction is…",
          "options": [
            "The stock rises sharply",
            "The stock falls",
            "Nothing happens"
          ],
          "answer": 1,
          "why": "Guidance changes expectations for the future, which matters more than one past quarter."
        },
        {
          "q": "Why are small earnings beats routine?",
          "options": [
            "Companies often guide conservatively",
            "Analysts are paid to be wrong",
            "Earnings are not audited"
          ],
          "answer": 0,
          "why": "Management usually sets beatable expectations, so a small beat carries little information."
        },
        {
          "q": "What should you compare the report with?",
          "options": [
            "The after-hours price move",
            "The thesis metric you wrote down beforehand",
            "Social media reactions"
          ],
          "answer": 1,
          "why": "Your own pre-written expectation turns the report into evidence for or against your thesis."
        }
      ]
    },
    {
      "slug": "thesis",
      "title": "Build a falsifiable stock thesis",
      "group": "Level 5 · Making decisions",
      "level": 5,
      "minutes": 5,
      "summary": "Writing down what you believe, what would prove you wrong, and when you will check — before you buy.",
      "opening": "The hardest part of investing is not finding ideas. It is remembering, eighteen months later, what you actually believed when you bought — and being honest about whether it happened. Memory is generous to itself. Writing is not.",
      "body": "A useful stock thesis states what the market may be missing, identifies the operating evidence that should close the gap, and defines what would prove the idea wrong. It is a testable decision record, not a prediction that the price will rise.",
      "points": [
        "Variant view: state what you believe differently from the market.",
        "Business driver: connect the view to revenue, margins, cash flow, or per-share value.",
        "Evidence: name the result or catalyst that would support the view.",
        "Failure condition: write the measurable fact that would invalidate it."
      ],
      "formula": "Thesis = Variant view + Business driver + Evidence + Failure condition",
      "example": "Example: recurring-revenue mix lifts operating margin faster than expected over the next four quarters.",
      "warning": "“The stock looks cheap” is not a thesis unless you explain why earnings or cash-flow expectations are wrong.",
      "closing": "A thesis you cannot falsify is not a thesis, it is a hope. The failure condition is the most valuable line in the whole document, and it is the one people most often leave out.",
      "tool": "analyze",
      "toolLabel": "Choose a stock to research",
      "tryIt": "Pick one company and write a four-line thesis: variant view, business driver, evidence, failure condition.",
      "quiz": [
        {
          "q": "Which line is the most important part of a thesis?",
          "options": [
            "The price target",
            "The failure condition",
            "The company's history"
          ],
          "answer": 1,
          "why": "It is what makes the thesis testable and tells you when to change your mind."
        },
        {
          "q": "Is 'the stock looks cheap' a thesis?",
          "options": [
            "Yes",
            "Only if you explain why expectations are wrong",
            "Only for large companies"
          ],
          "answer": 1,
          "why": "Cheapness needs a reason the market is mispricing future earnings or cash flow."
        }
      ]
    },
    {
      "slug": "portfolio-process",
      "title": "Build a portfolio and a review routine you will keep",
      "group": "Level 5 · Making decisions",
      "level": 5,
      "minutes": 6,
      "summary": "How many stocks to own, when to add or trim, and a simple quarterly review that keeps your theses honest.",
      "opening": "Buying a stock is one decision. Owning it is dozens of decisions over years, most of them made under the influence of the latest price move. A written process makes those later decisions consistent with the reasons you bought.",
      "body": "A portfolio is a set of theses, each with a size that reflects your confidence and its risk. A review routine checks each thesis against new evidence at fixed intervals, so you act on information rather than on volatility.",
      "points": [
        "Many individual investors hold 10–25 stocks: enough to diversify company risk, few enough to follow properly.",
        "Size by conviction and risk: larger for durable businesses you understand, smaller for speculative ideas.",
        "Trim when a position grows so large that one company dominates your results, or when valuation runs far ahead of the business.",
        "Sell when the thesis breaks, not when the price falls. Those are different events.",
        "Review quarterly: for each holding, is the thesis intact, has the valuation changed, and is the size still right?"
      ],
      "formula": "Review = Thesis intact? + Valuation still reasonable? + Size still right?",
      "example": "A holding has doubled and is now 18% of your portfolio. The business is performing as expected, but the valuation now implies growth well above your Base case. Trimming back to 8% keeps the exposure while banking part of the gain.",
      "warning": "Checking prices daily makes almost everyone trade more and do worse. Separate checking prices from making decisions.",
      "closing": "The best routine is the one you will keep. Thirty minutes a quarter with written notes beats daily attention without them.",
      "tool": "reports",
      "toolLabel": "Open your saved research",
      "tryIt": "Save one company with a thesis, a failure condition and a review date three months away.",
      "quiz": [
        {
          "q": "When should you sell a stock under this process?",
          "options": [
            "When it falls 10%",
            "When the thesis breaks",
            "Every quarter"
          ],
          "answer": 1,
          "why": "Price falls are not new information about the business; a broken thesis is."
        },
        {
          "q": "A winning stock grows to 25% of your portfolio. What is a reasonable response?",
          "options": [
            "Buy more, it is working",
            "Consider trimming to control concentration",
            "Sell everything immediately"
          ],
          "answer": 1,
          "why": "Trimming keeps exposure to the winner while limiting how much one company can hurt you."
        },
        {
          "q": "How often does this lesson suggest a full review?",
          "options": [
            "Every day",
            "Quarterly",
            "Never"
          ],
          "answer": 1,
          "why": "Quarterly matches the reporting cycle and avoids reacting to daily noise."
        }
      ]
    },
    {
      "slug": "behavioral-mistakes",
      "title": "The mistakes that cost investors the most",
      "group": "Level 5 · Making decisions",
      "level": 5,
      "minutes": 6,
      "summary": "Loss aversion, confirmation bias, anchoring and FOMO: how they show up in real decisions and the habits that defend against them.",
      "opening": "Most investing losses are not caused by bad analysis. They come from good investors making predictable human mistakes at the worst moments. You cannot switch these biases off, but you can build habits that catch them.",
      "body": "Behavioral biases are shortcuts the brain takes under uncertainty. In markets, they push people to buy after big rises, sell after big falls, hold losers too long and cut winners too early. The defence is process: decisions written down in advance, checked against evidence.",
      "points": [
        "Loss aversion: losses hurt about twice as much as equal gains feel good, so people hold losers hoping to break even.",
        "Confirmation bias: seeking information that agrees with you. Deliberately read the bear case for everything you own.",
        "Anchoring: fixating on your purchase price. The market does not know or care what you paid.",
        "FOMO and recency: chasing whatever has gone up most recently, usually near the top.",
        "Overconfidence: trading too often and sizing too large after a few wins."
      ],
      "formula": "Better decisions = Pre-commitment + Written evidence + Fixed review times",
      "example": "You bought at $100; it is now $60 and the thesis is broken. Holding 'until it gets back to $100' is anchoring. The only relevant question is whether you would buy it today at $60. If not, the money is better elsewhere.",
      "warning": "Feeling certain is not evidence. The moments you are most sure are usually the moments the crowd agrees with you, which is when prices already reflect it.",
      "closing": "Keep a decision journal: what you did, why, and what you expected. Reading it a year later is the most humbling and useful investing education there is.",
      "tool": "reports",
      "toolLabel": "Start a decision journal",
      "tryIt": "For a stock you own or like, write the strongest bear case you can in three sentences.",
      "quiz": [
        {
          "q": "You refuse to sell a broken idea until it gets back to your purchase price. Which bias is this?",
          "options": [
            "Anchoring",
            "Diversification",
            "Compounding"
          ],
          "answer": 0,
          "why": "Your purchase price is an anchor the market does not share."
        },
        {
          "q": "What is the best defence against confirmation bias?",
          "options": [
            "Only read bullish analysis",
            "Deliberately seek out the bear case",
            "Check the price more often"
          ],
          "answer": 1,
          "why": "Actively looking for disconfirming evidence counteracts the pull toward agreeable information."
        },
        {
          "q": "A stock tripled in three months and everyone is talking about it. Which bias tempts you to buy?",
          "options": [
            "FOMO and recency",
            "Loss aversion",
            "Anchoring"
          ],
          "answer": 0,
          "why": "Recent big gains create fear of missing out, often near the point of greatest risk."
        }
      ]
    },
    {
      "slug": "site-tour",
      "title": "Putting it together: one research workflow",
      "group": "Level 5 · Making decisions",
      "level": 5,
      "minutes": 4,
      "summary": "The research sequence ImpliedLens is built around, and why you do not need every tab for every stock.",
      "opening": "Most stock research goes wrong in the same way: you open twelve tabs, read whatever is loudest, and end up with an opinion you cannot reconstruct a week later. A process fixes that — not because it makes you right more often, but because it makes you able to tell, afterwards, why you were wrong.",
      "body": "The product is organized around a repeatable sequence. Start with the company and chart, verify the business evidence, test valuation, then record the decision. You do not need to visit every tab for every stock.",
      "points": [
        "Research: load a ticker and confirm the company, price, source badges, and as-of dates.",
        "Chart and LensScore: identify trend, key zones, tactical setup, long-term value, confidence, and active caps.",
        "Financials, Metrics, and Earnings: verify the operating evidence behind the score.",
        "Value or Projection: test a range of assumptions; do not treat one model output as truth.",
        "Saved or Planner: record the thesis, risks, failure condition, and review date."
      ],
      "formula": "Workflow = Identify → Verify → Value → Decide → Review",
      "example": "If LensValue is high but LensSetup is weak, add the company to Saved with a price zone and review date instead of forcing an entry.",
      "warning": "Do not jump from a green score to a trade. Confirm source dates, missing fields, and the evidence that could invalidate the idea.",
      "closing": "None of this requires you to visit every tab for every company. The sequence is there so you know what you have skipped. Most decisions die at step two, and that is the point — the cheapest research is the research that stops early.",
      "tool": "analyze",
      "toolLabel": "Open Research",
      "tryIt": "Run the full workflow on one company today: research, verify, value, decide, and set a review date.",
      "quiz": [
        {
          "q": "Where do most investment ideas end in this workflow?",
          "options": [
            "At the valuation step",
            "At the verify step",
            "They all get bought"
          ],
          "answer": 1,
          "why": "Most ideas fail verification, which is the cheapest place for research to stop."
        },
        {
          "q": "LensValue is high but LensSetup is weak. What does the lesson suggest?",
          "options": [
            "Force an entry now",
            "Save it with a price zone and review date",
            "Delete it from your list"
          ],
          "answer": 1,
          "why": "A good business at a poor entry is worth watching, not chasing."
        }
      ]
    }
  ];

  var BY_SLUG = {};
  LESSONS.forEach(function (l) { BY_SLUG[l.slug] = l; });

  return { lessons: LESSONS, bySlug: BY_SLUG };
});
