/*
 * scoring.js
 * Turns a list of detected indicators into a transparent 0-100 score and a
 * risk classification. Kept deliberately small and dependency-free so the maths
 * behind every result is easy to follow.
 */
(function (root) {
  'use strict';

  var MAX_SCORE = 100;

  // Classification thresholds. A score below LOW stays "Low Risk", below
  // SUSPICIOUS is "Suspicious", and anything higher is "High Risk".
  var THRESHOLDS = {
    suspicious: 30,
    high: 60
  };

  function classify(score) {
    if (score >= THRESHOLDS.high) return 'High Risk';
    if (score >= THRESHOLDS.suspicious) return 'Suspicious';
    return 'Low Risk';
  }

  function riskKey(score) {
    if (score >= THRESHOLDS.high) return 'high';
    if (score >= THRESHOLDS.suspicious) return 'suspicious';
    return 'low';
  }

  // Sum the points of every indicator, then cap at MAX_SCORE so a very long
  // list of small issues cannot push the number past the top of the scale.
  function compute(indicators) {
    var raw = 0;
    var highSeverity = 0;

    for (var i = 0; i < indicators.length; i++) {
      raw += indicators[i].points || 0;
      if (indicators[i].severity === 'high') highSeverity++;
    }

    var score = Math.min(raw, MAX_SCORE);

    return {
      score: score,
      rawScore: raw,
      capped: raw > MAX_SCORE,
      classification: classify(score),
      risk: riskKey(score),
      highSeverity: highSeverity,
      totalIndicators: indicators.length
    };
  }

  var api = {
    MAX_SCORE: MAX_SCORE,
    THRESHOLDS: THRESHOLDS,
    classify: classify,
    riskKey: riskKey,
    compute: compute
  };

  root.PhishingScoring = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
