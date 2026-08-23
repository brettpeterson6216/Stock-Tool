/* Compound calculator behaviour.
 *
 * This lived in an inline <script> in compound-calculator.html, which the
 * production CSP (script-src 'self') refused to execute — so the page rendered
 * its form and then did nothing at all: no results, no chart. Moving it to an
 * external file is what makes the calculator work.
 *
 * Depends on ImpliedLensMath (model-math.js) and Chart (chart.umd.min.js),
 * both loaded ahead of this file; `defer` preserves that order.
 */
let chart;
    const money=value=>Number(value).toLocaleString('en-US',{style:'currency',currency:'USD',maximumFractionDigits:0});
    function run(){
      const value=id=>Number(document.getElementById(id).value);
      const input={principal:value('principal'),monthlyContribution:value('monthly'),years:value('years'),baseReturn:value('return')/100,variance:value('variance')/100,inflation:value('inflation')/100};
      const results=document.getElementById('results');
      const out=ImpliedLensMath.compoundScenarios(input);if(!out.ok){results.innerHTML='<div class="note">'+out.error+'</div>';return}
      results.innerHTML=[['Low case',out.low.value],['Base case',out.base.value],['High case',out.high.value],["Today's dollars",out.realValue]].map(v=>'<div class="result"><span>'+v[0]+'</span><strong>'+money(v[1])+'</strong></div>').join('');
      if(chart)chart.destroy();chart=new Chart(document.getElementById('chart'),{type:'line',data:{labels:out.base.path.map(p=>'Year '+Math.round(p.month/12)),datasets:[{label:'High',data:out.high.path.map(p=>p.value),borderColor:'#247757',pointRadius:0},{label:'Base',data:out.base.path.map(p=>p.value),borderColor:'#76521d',borderWidth:2.5,pointRadius:0},{label:'Low',data:out.low.path.map(p=>p.value),borderColor:'#a94f55',pointRadius:0},{label:'Contributions',data:out.base.path.map(p=>p.contributions),borderColor:'#66717b',borderDash:[4,4],pointRadius:0}]},options:{responsive:true,maintainAspectRatio:false,interaction:{mode:'index',intersect:false},plugins:{tooltip:{callbacks:{label:c=>c.dataset.label+': '+money(c.raw)}}},scales:{x:{grid:{display:false}},y:{ticks:{callback:money}}}}});
    }
    document.getElementById('run').addEventListener('click',run);run();
