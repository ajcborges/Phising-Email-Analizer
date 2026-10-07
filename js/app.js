/*
 * app.js
 * Connects the page to the analysis engine: reads the pasted email, runs the
 * analyser, and renders the score, the reasons and the recommendations.
 * It only touches the DOM - it never sends anything over the network.
 */
(function () {
  'use strict';

  // Matches the SVG circle's dash length (2 * PI * radius, radius = 52).
  var GAUGE_CIRCUMFERENCE = 326.73;
  var els = {};

  function $(id) { return document.getElementById(id); }

  function init() {
    els.input = $('emailInput');
    els.analyseBtn = $('analyseBtn');
    els.clearBtn = $('clearBtn');
    els.charCount = $('charCount');
    els.demoButtons = $('demoButtons');
    els.resultsEmpty = $('resultsEmpty');
    els.resultsContent = $('resultsContent');
    els.gauge = $('gauge');
    els.gaugeFill = $('gaugeFill');
    els.gaugeScore = $('gaugeScore');
    els.riskBadge = $('riskBadge');
    els.riskTitle = $('riskTitle');
    els.riskSubtitle = $('riskSubtitle');
    els.statIndicators = $('statIndicators');
    els.statHigh = $('statHigh');
    els.statUrls = $('statUrls');
    els.indicatorList = $('indicatorList');
    els.recommendationList = $('recommendationList');

    buildDemoButtons();

    els.analyseBtn.addEventListener('click', runAnalysis);
    els.clearBtn.addEventListener('click', clearAll);
    els.input.addEventListener('input', updateCharCount);
    els.input.addEventListener('keydown', function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') runAnalysis();
    });

    updateCharCount();
  }

  function buildDemoButtons() {
    var demos = (typeof globalThis !== 'undefined' && globalThis.DEMO_EMAILS) || [];
    demos.forEach(function (demo) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'demo-btn';
      btn.textContent = demo.label;
      btn.title = 'Load a fictional example (' + demo.hint + ')';
      btn.addEventListener('click', function () {
        els.input.value = demo.text;
        updateCharCount();
        runAnalysis();
      });
      els.demoButtons.appendChild(btn);
    });
  }

  function updateCharCount() {
    var n = els.input.value.length;
    els.charCount.textContent = n.toLocaleString() + (n === 1 ? ' character' : ' characters');
  }

  function clearAll() {
    els.input.value = '';
    updateCharCount();
    els.resultsContent.hidden = true;
    els.resultsEmpty.hidden = false;
    els.input.focus();
  }

  function runAnalysis() {
    var text = els.input.value;
    if (!text.trim()) {
      els.input.focus();
      return;
    }
    var result = globalThis.PhishingAnalyser.analyse(text);
    renderResult(result);
  }

  function titleFor(risk) {
    if (risk === 'high') return 'High Risk \u2014 treat as dangerous';
    if (risk === 'suspicious') return 'Suspicious \u2014 verify before acting';
    return 'Low Risk \u2014 no obvious warning signs';
  }

  function subtitleFor(risk, s) {
    if (s.totalIndicators === 0) {
      return 'None of our checks found a warning sign. That is not a guarantee the email is safe \u2014 stay cautious.';
    }
    var n = s.totalIndicators;
    var base = n + (n === 1 ? ' warning sign' : ' warning signs') + ' detected';
    if (s.capped) base += ' (raw total ' + s.rawScore + ', capped at 100)';
    return base + '. See the explanations below.';
  }

  function renderResult(result) {
    var s = result.summary;

    els.resultsEmpty.hidden = true;
    els.resultsContent.hidden = false;

    // Gauge: set colour, number and animated ring.
    els.gauge.setAttribute('data-risk', s.risk);
    els.gaugeScore.textContent = String(s.score);
    els.gaugeFill.style.strokeDashoffset = GAUGE_CIRCUMFERENCE;
    var target = GAUGE_CIRCUMFERENCE * (1 - s.score / 100);
    window.requestAnimationFrame(function () {
      els.gaugeFill.style.strokeDashoffset = target;
    });

    // Badge and text.
    els.riskBadge.textContent = s.classification;
    els.riskBadge.setAttribute('data-risk', s.risk);
    els.riskTitle.textContent = titleFor(s.risk);
    els.riskSubtitle.textContent = subtitleFor(s.risk, s);

    // Summary stats.
    els.statIndicators.textContent = String(s.totalIndicators);
    els.statHigh.textContent = String(s.highSeverity);
    els.statUrls.textContent = String(result.stats.urls);

    renderIndicators(result.indicators);
    renderRecommendations(result.recommendations);

    if (window.innerWidth < 940) {
      els.resultsContent.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  function renderIndicators(indicators) {
    els.indicatorList.innerHTML = '';

    if (!indicators.length) {
      var card = document.createElement('li');
      card.className = 'clean-card';
      card.textContent = 'No warning signs were detected by our checks. Stay cautious \u2014 this tool cannot prove an email is safe.';
      els.indicatorList.appendChild(card);
      return;
    }

    indicators.forEach(function (ind) {
      var li = document.createElement('li');
      li.className = 'indicator sev-' + ind.severity;

      var top = document.createElement('div');
      top.className = 'indicator-top';

      var nameWrap = document.createElement('div');
      var name = document.createElement('div');
      name.className = 'indicator-name';
      name.textContent = ind.label;
      var cat = document.createElement('div');
      cat.className = 'indicator-cat';
      cat.textContent = ind.category;
      nameWrap.appendChild(name);
      nameWrap.appendChild(cat);

      var pts = document.createElement('span');
      pts.className = 'indicator-points';
      pts.textContent = '+' + ind.points;

      top.appendChild(nameWrap);
      top.appendChild(pts);
      li.appendChild(top);

      var why = document.createElement('p');
      why.className = 'indicator-why';
      why.textContent = ind.explanation;
      li.appendChild(why);

      if (ind.evidence && ind.evidence.length) {
        var ev = document.createElement('div');
        ev.className = 'indicator-evidence';
        ind.evidence.forEach(function (text) {
          var chip = document.createElement('span');
          chip.className = 'evidence-chip';
          chip.textContent = text;
          ev.appendChild(chip);
        });
        li.appendChild(ev);
      }

      els.indicatorList.appendChild(li);
    });
  }

  function renderRecommendations(recs) {
    els.recommendationList.innerHTML = '';
    recs.forEach(function (text) {
      var li = document.createElement('li');
      li.textContent = text;
      els.recommendationList.appendChild(li);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
