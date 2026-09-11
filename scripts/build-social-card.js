/* The Open Graph / Twitter card: public/social-card.png, 1200x630.

   This is its own script rather than part of build-brand.js because the chart
   on it is not drawn — it is rendered by the site's own charting engine.
   public/vendor/lightweight-charts.standalone.production.js is loaded here and
   configured the way public/hero-chart.js configures it (candlesticks, the
   30-day average, the gold last-price line), then given 92 real daily AAPL
   bars from brand/social-card-data.json. A card for a stock research tool
   should not show a hand-drawn squiggle standing in for a chart; this one
   shows the product's actual output on actual market data, including the real
   gap down on 2026-07-31 and the recovery after it.

   Run:  node scripts/build-social-card.js
   Needs: playwright-core + a chromium, and python3 with Pillow. Both are dev
   tools, so this is NOT part of `npm run check:brand` or the test suite -- the
   tests assert the committed PNG's shape and that every page points at it.

   Rendered at 2x and downsampled, because 1x browser text at this size is
   noticeably softer and the card is the first thing anyone sees of the site.
*/
"use strict";

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const ROOT = path.join(__dirname, "..");
const P = (...p) => path.join(ROOT, ...p);
const OUT = P("public", "social-card.png");
const W = 1200, H = 630;

const b64 = (p) => fs.readFileSync(P(p)).toString("base64");
const DATA = JSON.parse(fs.readFileSync(P("brand", "social-card-data.json"), "utf8"));

function buildHtml() {
  const rows = DATA.rows;
  const last = rows[rows.length - 1][4];
  const prev = rows[rows.length - 2][4];
  const chg = ((last - prev) / prev) * 100;
  const lwc = fs.readFileSync(P("public", "vendor", "lightweight-charts.standalone.production.js"), "utf8");

  return `<!doctype html><meta charset="utf-8">
<style>
@font-face{font-family:PJS;src:url(data:font/ttf;base64,${b64("brand/fonts/PlusJakartaSans-Regular.ttf")}) format('truetype');font-weight:400}
@font-face{font-family:PJS;src:url(data:font/ttf;base64,${b64("brand/fonts/PlusJakartaSans-Bold.ttf")}) format('truetype');font-weight:700}
*{margin:0;padding:0;box-sizing:border-box}
html,body{width:${W}px;height:${H}px}
body{font-family:PJS,sans-serif;background:#100f0e;color:#f2efe6;overflow:hidden}
.card{position:relative;width:${W}px;height:${H}px;background:#100f0e;overflow:hidden}
/* the warm field the site's heroes sit in, kept low so the graphite survives */
.glow{position:absolute;width:600px;height:600px;left:-230px;top:-40px;border-radius:50%;
      background:#5a3c0c;filter:blur(130px);opacity:.32}
.mark{position:absolute;left:64px;top:167px;width:296px;height:296px}
.col{position:absolute;left:418px;top:74px;width:718px}
.wm{font-weight:700;font-size:62px;line-height:1;letter-spacing:-.045em}
.wm span{color:#efb133}
.panel{margin-top:22px;background:#151412;border:1px solid #262320;border-radius:14px;padding:16px 18px 10px}
.rd{display:flex;justify-content:space-between;align-items:baseline}
.tk{font-size:25px;font-weight:700;letter-spacing:-.03em}
.nm{font-size:15px;color:#9d988c;margin-left:9px}
.px{font-size:22px;font-weight:700;letter-spacing:-.02em}
.chg{color:#2FD98C;font-size:16px;font-weight:700;margin-left:9px}
#ch{height:196px;margin-top:8px}
.src{margin-top:4px;font-size:11px;letter-spacing:.05em;color:#6f6a62}
/* Held above y=530: X paints its own title chip across the bottom-left of
   the card, and it will sit on top of anything down there. */
.tag{margin-top:20px;font-size:27px;line-height:1.35;color:#c6c1b5;letter-spacing:-.012em}
.dom{position:absolute;right:66px;bottom:44px;font-weight:700;font-size:18px;letter-spacing:.24em;color:#8d887d}
</style>
<div class="card">
  <div class="glow"></div>
  <img class="mark" src="data:image/png;base64,${b64("public/logo-mark.png")}" alt="">
  <div class="col">
    <div class="wm">Implied<span>Lens</span></div>
    <div class="panel">
      <div class="rd">
        <div><span class="tk">${DATA.symbol}</span><span class="nm">${DATA.name} &middot; ${DATA.exchange}</span></div>
        <div><span class="px">${last.toFixed(2)}</span><span class="chg">+${chg.toFixed(2)}%</span></div>
      </div>
      <div id="ch"></div>
      <div class="src">DAILY CANDLES &middot; 30-DAY AVERAGE &middot; ${DATA.from} &ndash; ${DATA.to}</div>
    </div>
    <div class="tag">Research the business. Test the thesis.<br>Revisit the decision.</div>
  </div>
  <div class="dom">IMPLIEDLENS.COM</div>
</div>
<script>${lwc}</script>
<script>
const ROWS = ${JSON.stringify(rows)};
function sma(v,n){const o=[];let s=0;for(let i=0;i<v.length;i++){s+=v[i];if(i>=n)s-=v[i-n];o.push(i>=n-1?s/n:null);}return o;}
const up = '#2FD98C', down = '#F05C6A';
const c = LightweightCharts.createChart(document.getElementById('ch'), {
  layout:{ background:{type:'solid',color:'transparent'}, textColor:'#8E8A82',
           fontFamily:'PJS, sans-serif', fontSize:11, attributionLogo:false },
  grid:{ vertLines:{visible:false}, horzLines:{color:'rgba(255,255,255,.05)'} },
  rightPriceScale:{ visible:true, borderVisible:false, scaleMargins:{top:.10,bottom:.08} },
  timeScale:{ visible:true, borderVisible:false, rightOffset:1, fixLeftEdge:true, fixRightEdge:true },
  crosshair:{ mode:0, vertLine:{visible:false,labelVisible:false}, horzLine:{visible:false,labelVisible:false} },
  handleScroll:false, handleScale:false, autoSize:true
});
const s = c.addSeries(LightweightCharts.CandlestickSeries, {
  upColor:up, downColor:down, borderUpColor:up, borderDownColor:down, wickUpColor:up, wickDownColor:down,
  priceLineVisible:true, priceLineColor:'#D6AC64', priceLineStyle:2, priceLineWidth:1
});
s.setData(ROWS.map(r=>({time:r[0],open:r[1],high:r[2],low:r[3],close:r[4]})));
const ma = c.addSeries(LightweightCharts.LineSeries, {
  color:'#7FB2E5', lineWidth:2, priceLineVisible:false, lastValueVisible:false, crosshairMarkerVisible:false });
const avg = sma(ROWS.map(r=>r[4]), 30);
ma.setData(ROWS.map((r,i)=>avg[i]==null?null:{time:r[0],value:avg[i]}).filter(Boolean));
c.timeScale().fitContent();
window.__cardReady = true;
</script>`;
}

(async () => {
  let chromium;
  try { ({ chromium } = require("playwright-core")); }
  catch (_) { ({ chromium } = require("/root/node_modules/playwright-core")); }

  const tmp = path.join(require("os").tmpdir(), "social-card-2x.png");
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || "/opt/pw-browsers/chromium" });
  const ctx = await browser.newContext({ viewport: { width: W, height: H }, deviceScaleFactor: 2 });
  const page = await ctx.newPage();
  await page.setContent(buildHtml());
  await page.waitForFunction(() => window.__cardReady === true, { timeout: 20000 });
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(600);
  await page.screenshot({ path: tmp });
  await browser.close();

  execFileSync("python3", ["-c", `
import sys
from PIL import Image
im = Image.open(sys.argv[1]).convert("RGB").resize((${W}, ${H}), Image.LANCZOS)
im.save(sys.argv[2], "PNG", optimize=True)
`, tmp, OUT]);

  const kb = fs.statSync(OUT).size / 1024;
  console.log(`Built public/social-card.png  ${W}x${H}  ${kb.toFixed(1)} KB`);
  console.log(`  chart: ${DATA.rows.length} real daily ${DATA.symbol} bars, ${DATA.from} to ${DATA.to} (${DATA.source})`);
})();
