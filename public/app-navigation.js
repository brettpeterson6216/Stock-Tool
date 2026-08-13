  // ── View + nav controller ──
  // Each top-level tab owns its own left panel. The panel only switches sections
  // WITHIN the active tab — it can never change which top tab you're on.
  const NAV_GROUPS = {
    research:    ['analyze','financials','advmetrics','earnings','calls','secfilings','institutional','screener'],
    projections: ['projection','dcf'],
    comparison:  ['compare'],
    planner:     ['wealth'],
    learn:       ['education'],
    saved:       ['reports','workspace'],
  };
  const NAV_GROUP_TAB   = { research:'nav-analyze', projections:'nav-project', comparison:'nav-compare', planner:'nav-planner', learn:'nav-education-link', saved:'nav-saved-link' };
  const NAV_GROUP_LABEL = { research:'Research', projections:'Scenarios', comparison:'Compare', planner:'Planner', learn:'Learn', saved:'Saved' };
  function navGroupOf(sec) {
    for (const g in NAV_GROUPS) if (NAV_GROUPS[g].includes(sec)) return g;
    return 'research';
  }
  function renderSidebarGroup(group) {
    const items = NAV_GROUPS[group] || [];
    document.querySelectorAll('.app-sidebar .sb-item').forEach(it => {
      it.style.display = items.includes(it.dataset.sec) ? '' : 'none';
    });
    const lbl = document.querySelector('.app-sidebar .sb-group-label');
    if (lbl) lbl.textContent = NAV_GROUP_LABEL[group] || 'Research';
    document.getElementById('view-tool')?.setAttribute('data-nav-group', group);
  }
  window.renderSidebarGroup = renderSidebarGroup;
  function marketScrollTo(key) {
    const map = { top: '.home-hero', breadth: '#mo-advancing', movers: '#home-movers-list', insights: '#home-insights-list' };
    document.querySelectorAll('.hs-sidebar .hsb-item').forEach(a => a.classList.toggle('active', a.dataset.mk === key));
    const el = document.querySelector(map[key]);
    if (!el) return;
    if (key === 'top') { window.scrollTo({ top: 0, behavior: 'smooth' }); return; }
    (el.closest('.hc,.hg-market,.hl-report,section') || el).scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  function landingScrollTo(sel, link) {
    document.querySelectorAll('.il-landing-rail a').forEach(a => a.classList.toggle('active', a === link));
    if (sel === 'top') { window.scrollTo({ top: 0, behavior: 'smooth' }); return; }
    document.querySelector(sel)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  function setHomeMode(mode) {
    const landing = document.getElementById('landing-page');
    const market = document.getElementById('market-page');
    if (landing) landing.style.display = mode === 'market' ? 'none' : 'block';
    if (market) market.style.display = mode === 'market' ? 'flex' : 'none';
    document.querySelectorAll('.nav-tab').forEach(a => a.classList.remove('active-tab'));
    const active = document.getElementById(mode === 'market' ? 'nav-market' : 'nav-home') || document.getElementById('nav-home');
    if (active) active.classList.add('active-tab');
    const homeBtn = document.querySelector('.hsb-home');
    if (homeBtn) homeBtn.classList.toggle('active', mode === 'market');
  }

  function showLandingPage() {
    const home = document.getElementById('view-home');
    const tool = document.getElementById('view-tool');
    if (tool) tool.style.display = 'none';
    if (home) home.style.display = 'block';
    const nav = document.getElementById('main-nav'); if(nav) nav.setAttribute('data-view','home');
    setHomeMode('landing');
    history.replaceState(null, '', '/');
  }

  function showMarketPage() {
    const home = document.getElementById('view-home');
    const tool = document.getElementById('view-tool');
    if (tool) tool.style.display = 'none';
    if (home) home.style.display = 'block';
    const nav = document.getElementById('main-nav'); if(nav) nav.setAttribute('data-view','home');
    setHomeMode('market');
    history.replaceState(null, '', '/?view=home&market=1');
    if (typeof initializeHomeDashboard === 'function') initializeHomeDashboard();
  }

  function showView(view) {
    const home = document.getElementById('view-home');
    const tool = document.getElementById('view-tool');
    if (view === 'tool') {
      if (home) home.style.display = 'none';
      if (tool) { tool.style.display = 'flex'; tool.style.flexDirection = 'column'; }
      const activeSection = new URLSearchParams(window.location.search).get('section');
      history.replaceState(null, '', '/?view=tool' + (activeSection ? '&section=' + encodeURIComponent(activeSection) : ''));
      const nav = document.getElementById('main-nav'); if(nav) nav.setAttribute('data-view','tool');
      document.querySelectorAll('.nav-tab').forEach(a => a.classList.remove('active-tab'));
      var _sec = activeSection || document.getElementById('view-tool')?.getAttribute('data-active-section') || 'analyze';
      var _grp = (typeof navGroupOf==='function') ? navGroupOf(_sec) : 'research';
      var _tabId = (typeof NAV_GROUP_TAB!=='undefined' && NAV_GROUP_TAB[_grp]) ? NAV_GROUP_TAB[_grp] : 'nav-analyze';
      var tt = document.getElementById(_tabId); if(tt) tt.classList.add('active-tab');
    } else {
      showLandingPage();
    }
  }

  function setActiveNavTab(toolId) {
    document.querySelectorAll('.nav-tab').forEach(a => a.classList.remove('active-tab'));
    if (toolId === 'home') {
      const el = document.getElementById('nav-home');
      if (el) el.classList.add('active-tab');
    } else if (toolId) {
      const el = document.querySelector('.nav-tab[data-tool="'+toolId+'"]');
      if (el) el.classList.add('active-tab');
    }
  }

  function navSearchGo(e) {
    if (e) e.preventDefault();
    var el = document.getElementById('nav-ticker-input');
    var v = (el && el.value || '').trim();
    if (!v) { if (el) el.focus(); return false; }
    if (el) el.blur();
    if (typeof heroLoadTicker === 'function') heroLoadTicker(v.toUpperCase());
    return false;
  }
  window.navSearchGo = navSearchGo;
  function navGoTo(id, attempt) {
    if (id === 'adveducation') id = 'education';
    if (id === 'home') { showLandingPage(); updateNavToolLink(true); return; }
    if (typeof openSection !== 'function' || !document.getElementById('sec-' + id)) {
      const nextAttempt = (attempt || 0) + 1;
      if (nextAttempt <= 100) setTimeout(() => navGoTo(id, nextAttempt), 50);
      return;
    }
    showView('tool');
    window.scrollTo(0,0);
    openSection(id); // no skipProCheck — free users see the upgrade modal, not empty Pro panels
    history.replaceState(null, '', '/?view=tool&section=' + encodeURIComponent(id));
  }

  // On hard load: respect ?view=tool or ?view=home in URL
  // Must wait for DOM since #view-home / #view-tool are defined after this <nav>
  document.addEventListener('DOMContentLoaded', function() {
    const params = new URLSearchParams(window.location.search);
    const requestedSection = params.get('section');
    window.__initialWorkspaceTab = params.get('workspace_tab');
    if (params.get('view') === 'tool') {
      showView('tool');
      setTimeout(() => navGoTo(requestedSection || 'analyze'), 0); // always resolve a section so the tab + left panel group render correctly
    }
    else if (params.get('market') === '1') {
      showMarketPage();
    }
    else {
      showLandingPage();
    }
    // Modules (Calls, Wealth, Workspace) inject sidebar items shortly after load —
    // re-apply the active group filter so late items respect the current tab.
    [900, 2500, 5000].forEach(function(ms){
      setTimeout(function(){
        var vt = document.getElementById('view-tool');
        if (vt && vt.style.display !== 'none') renderSidebarGroup(vt.getAttribute('data-nav-group') || 'research');
      }, ms);
    });
  });

  // ── Account dropdown toggle ──
  function toggleAcctMenu(e) {
    e.stopPropagation();
    document.getElementById('nav-acct-wrap').classList.toggle('open');
  }
  document.addEventListener('click', () => {
    const w = document.getElementById('nav-acct-wrap');
    if (w) w.classList.remove('open');
  });

  // ---- Auth-aware nav (talks to /api/auth/me + /api/auth/logout) ----

  function _dismissVeil() {
    var v = document.getElementById('auth-veil');
    if (!v) return;
    v.classList.add('done');
    setTimeout(function(){ if(v && v.parentNode) v.parentNode.removeChild(v); }, 220);
  }
  function trackWhenReady(event, props, attempt) {
    if (typeof track === 'function') {
      track(event, props);
      return;
    }
    const nextAttempt = (attempt || 0) + 1;
    if (nextAttempt <= 100) setTimeout(() => trackWhenReady(event, props, nextAttempt), 50);
  }
  setTimeout(_dismissVeil, 4000);
  let _resolveAuthReady;
  window.IL_AUTH_READY = new Promise(resolve => { _resolveAuthReady = resolve; });
  (async () => {
    const $login     = document.getElementById('nav-login');
    const $signup    = document.getElementById('nav-signup');
    const $upgrade   = document.getElementById('nav-upgrade');
    const $guide     = document.getElementById('nav-guide-link');
    const $acctWrap  = document.getElementById('nav-acct-wrap');
    const $acctName  = document.getElementById('nav-acct-name');
    const $acctBadge = document.getElementById('nav-acct-badge');
    const $acctHdrName = document.getElementById('nav-acct-header-name');
    const $acctHdrPlan = document.getElementById('nav-acct-header-plan');
    const $acctLogout  = document.getElementById('nav-acct-logout');
    const _initialParams = new URLSearchParams(window.location.search);

    try {
      const [meRes, csrfRes] = await Promise.all([
        fetch('/api/auth/me', { credentials: 'same-origin' }),
        fetch('/api/csrf',    { credentials: 'same-origin' }),
      ]);
      const { user } = await meRes.json();
      const csrfData = await csrfRes.json().catch(() => ({}));
      if (typeof S !== 'undefined' && csrfData.token) S.csrfToken = csrfData.token;
      if (user) {
        // Hide login / signup buttons
        $login.style.display  = 'none';
        $signup.style.display = 'none';
        if ($guide) $guide.style.display = '';

        // Store plan state globally
        if (typeof S !== 'undefined') {
          S.userPlan      = user.effectivePlan || 'free';
          S.trialEndsAt   = user.trial_ends_at || null;
          S.loggedIn      = true;
          S.emailVerified = user.email_verified ? true : false;
          if (typeof syncPlanUI === 'function') syncPlanUI();
        }
        // Show verification banner if email unverified
        if (!user.email_verified) {
          const _vb = document.getElementById('verif-banner');
          if (_vb) {
            _vb.style.display = 'flex';
            document.body.classList.add('has-verif-banner');
          }
        }

        // Populate account dropdown
        $acctName.textContent = user.username || user.email;
        $acctHdrName.textContent = user.username || user.email;
        $acctWrap.style.display = 'block';

        if (user.effectivePlan === 'pro') {
          $acctBadge.textContent = 'PRO';
          $acctBadge.style.display = 'inline';
          $acctHdrPlan.textContent = 'Pro member';
          $acctHdrPlan.style.color = 'var(--gold-d)';
        } else if (user.effectivePlan === 'trial') {
          const trialEnd = user.trial_ends_at ? new Date(user.trial_ends_at) : null;
          const daysLeft = trialEnd ? Math.max(0, Math.ceil((trialEnd - Date.now()) / 86400000)) : null;
          const trialExpiry = trialEnd ? trialEnd.toLocaleDateString('en-US', {month:'short', day:'numeric', year:'numeric'}) : '';
          $acctBadge.textContent = 'TRIAL';
          $acctBadge.className = 'nav-acct-badge trial';
          $acctBadge.style.display = 'inline';
          $acctHdrPlan.textContent = daysLeft !== null
            ? `Trial · ${daysLeft} day${daysLeft !== 1 ? 's' : ''} remaining (expires ${trialExpiry})`
            : 'Trial member';
          $acctHdrPlan.style.color = daysLeft !== null && daysLeft <= 3 ? '#e67e22' : 'var(--ink3)';
        } else {
          // Free user — show upgrade button
          $acctHdrPlan.textContent = 'Free plan';
          if ($upgrade) $upgrade.style.display = 'inline-block';
        }

        if (typeof decorateProTabs !== 'undefined') decorateProTabs();
        // Sync saved analyses from DB
        if (typeof syncSavesFromDB === 'function') syncSavesFromDB();

        // Logged-in users go straight to tool view unless they explicitly came home
        if (_initialParams.get('view') !== 'home') {
          showView('tool');
        }

        // Hide PRO feature badges for paying/trial members
        if (typeof isPro === 'function' && isPro()) {
          document.querySelectorAll('.feat-pro').forEach(el => el.style.display = 'none');
        }

        // Update hero + pricing section for logged-in pro/trial users
        if (typeof isPro === 'function' && isPro()) {
          const heroMain = document.getElementById('hero-cta-main');
          const heroSec  = document.getElementById('hero-cta-secondary');
          if (heroMain) { heroMain.textContent = 'Open live tool →'; heroMain.removeAttribute('onclick'); heroMain.href='#'; heroMain.onclick=function(e){e.preventDefault();navGoTo('analyze');}; }
          if (heroSec)  heroSec.style.display = 'none';

          // New landing hero (banner mode) — don't pitch "free"/"trial" to existing Pro members.
          const ilP = document.getElementById('il-hero-primary');
          if (ilP) { ilP.innerHTML = '<i class="ti ti-player-play"></i> Open live tool'; ilP.onclick = function(){ navGoTo('analyze'); }; }
          const ilS = document.getElementById('il-hero-secondary');
          if (ilS) ilS.style.display = 'none';
          const ilNoCard = document.getElementById('il-trust-nocard');
          if (ilNoCard) ilNoCard.style.display = 'none';
          const ilNoCardDot = document.getElementById('il-trust-nocard-dot');
          if (ilNoCardDot) ilNoCardDot.style.display = 'none';
          const ilLede = document.getElementById('il-lede-sub');
          if (ilLede) ilLede.textContent = 'Turn any ticker into live charts, SEC-sourced financials, valuation and projection models, and a saved thesis.';
          const ilPricing = document.getElementById('landing-pricing');
          if (ilPricing) ilPricing.style.display = 'none';

          const pricingSection = document.getElementById('pricing');
          const proBanner      = document.getElementById('pro-member-banner');
          if (pricingSection) pricingSection.style.display = 'none';
          if (proBanner)      proBanner.style.display = 'block';

          const ctaMain  = document.getElementById('cta-btn-main');
          const ctaPlans = document.getElementById('cta-btn-plans');
          if (ctaMain)  { ctaMain.textContent = 'Open Pro tool →'; ctaMain.href = '#'; ctaMain.onclick = function(e){ e.preventDefault(); navGoTo('analyze'); }; }
          if (ctaPlans) { ctaPlans.style.display = 'none'; }

          if (user.trial_ends_at) {
            const days = Math.max(0, Math.ceil((new Date(user.trial_ends_at) - Date.now()) / 86400000));
            const daysEl = document.getElementById('pro-banner-days');
            if (daysEl) daysEl.textContent = days;
          }
          if (user.effectivePlan === 'pro') {
            const title = document.getElementById('pro-banner-title');
            const sub   = document.getElementById('pro-banner-sub');
            if (title) title.innerHTML = "You're on <em style=\"font-style:italic;color:var(--gold-d);\">Pro</em>.";
            if (sub)   sub.textContent = 'All Pro features are active. Thank you for subscribing.';
          }
        }

        // Auto-show upgrade success toast
        if (_initialParams.get('upgraded') === '1') {
          if (typeof toast !== 'undefined') toast('Welcome to Pro! All features unlocked.', 'ok');
          history.replaceState(null, '', '/');
          trackWhenReady('checkout_redirect', { source: 'stripe_success' });
        }
        if (_initialParams.get('checkout') === 'cancelled') {
          if (typeof toast !== 'undefined') toast('Checkout cancelled. Your plan was not changed.');
          trackWhenReady('checkout_cancelled', { source: 'stripe_checkout' });
          history.replaceState(null, '', '/');
        }
        // Email verification result toasts
        const _verifParam = _initialParams.get('verif');
        if (_verifParam === 'ok') {
          toast('Email verified! You can now start your trial.', 'ok');
          if (typeof S !== 'undefined') S.emailVerified = true;
          const _vb = document.getElementById('verif-banner');
          if (_vb) _vb.style.display = 'none';
          document.body.classList.remove('has-verif-banner');
          history.replaceState(null, '', '/');
        } else if (_verifParam === 'expired') {
          toast('Verification link expired. Please request a new one.', 'err');
          history.replaceState(null, '', '/');
        } else if (_verifParam === 'invalid') {
          toast('Invalid verification link.', 'err');
          history.replaceState(null, '', '/');
        } else if (_verifParam === 'already') {
          toast('Email already verified.', 'ok');
          history.replaceState(null, '', '/');
        }
        // Resume checkout after auth (from upgrade modal → signup/login)
        const _resumePlan = sessionStorage.getItem('pendingUpgradePlan');
        if (_resumePlan && _initialParams.get('resume_checkout') === '1') {
          history.replaceState(null, '', '/');
          trackWhenReady('checkout_resumed_after_auth', { plan: _resumePlan });
          if (typeof S !== 'undefined' && !S.emailVerified) {
            _upgradePlan = _resumePlan;
            showUpgradeModal(_resumePlan === 'annual', 'checkout_resume_unverified');
            document.getElementById('upgrade-modal-unverified').style.display = 'block';
            trackWhenReady('checkout_blocked_unverified', { plan: _resumePlan, source: 'checkout_resume' });
          } else if (typeof startTrial === 'function') {
            sessionStorage.removeItem('pendingUpgradePlan');
            setTimeout(() => startTrial(_resumePlan === 'annual'), 800);
          }
        }
      }
    } catch (_) { /* server not running */ } finally {
      // Show Go Pro banner only for free/guest users
      const _plan = (typeof S !== 'undefined' && S.userPlan) || 'free';
      const _ub = document.getElementById('hsb-upgrade-box');
      if (_ub) {
        if (_plan === 'pro' || _plan === 'trial') {
          _ub.style.display = 'none'; // explicitly hide for paying users
        } else {
          _ub.style.display = ''; // show for free/guest
        }
      }
      if (typeof syncPlanUI === 'function') syncPlanUI();
      if (typeof S !== 'undefined') S.authReady = true;
      if (_resolveAuthReady) _resolveAuthReady();
      trackWhenReady('page_view', {
        plan: (typeof S !== 'undefined' && S.loggedIn) ? _plan : 'guest',
        logged_in: !!(typeof S !== 'undefined' && S.loggedIn),
      });
      _dismissVeil();
      // Auto-load analyzer from ?ticker= OR ?symbol= query param.
      // (syncToolUrl writes ?symbol=, landing CTAs write ?ticker= — accept both.)
      (function _handleTickerParam() {
        const _params = _initialParams;
        const _t = _params.get('ticker') || _params.get('symbol');
        if (!_t) return;
        const _clean = _t.toUpperCase().replace(/[^A-Z0-9.\-^]/g, '').slice(0, 10);
        if (!_clean) return;
        const _range = _params.get('range');
        if (typeof S !== 'undefined' && ['1d','5d','1mo','3mo','6mo','1y','2y','5y','10y','max'].includes(_range)) {
          S.range = _range;
        }
        if (_params.get('resume_analysis') === '1') {
          trackWhenReady('analysis_resumed_after_auth', { ticker: _clean, source: _params.get('source') || 'auth_return' });
        }
        const _mi = document.getElementById('main-ticker');
        if (_mi) _mi.value = _clean;
        // Honor the requested tool section (projection, financials, …) instead of
        // always forcing analyze. fetchAndRender re-mounts whichever section is open.
        const _reqSec = _params.get('section');
        const _targetSec = (_reqSec && document.getElementById('sec-' + _reqSec)) ? _reqSec : 'analyze';
        history.replaceState(null, '', '/?view=tool&section=' + encodeURIComponent(_targetSec));
        (function _openTicker(attempt) {
          if (typeof openSection !== 'function' || typeof fetchAndRender !== 'function') {
            if (attempt < 100) setTimeout(() => _openTicker(attempt + 1), 50);
            return;
          }
          navGoTo(_targetSec);
          fetchAndRender();
        })(0);
      })();
    }

    // Logout
    if ($acctLogout) {
      $acctLogout.addEventListener('click', async (e) => {
        e.preventDefault();
        await fetch('/api/auth/logout', { method:'POST', credentials:'same-origin', headers:{'X-CSRF-Token': S.csrfToken||''} });
        window.location.href = '/login';
      });
    }
    if ($upgrade) {
      $upgrade.addEventListener('click', (e) => { e.preventDefault(); showUpgradeModal(); });
    }
  })();
