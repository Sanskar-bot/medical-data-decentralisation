/**
 * record-save.js — MedVault shared record-save helper
 *
 * Provides window.MV.saveRecord(password, partial, onDone) so both
 * health_record.html and onboarding.html can POST to /patient/record
 * without duplicating the fetch logic.
 *
 * Usage:
 *   MV.saveRecord(password, { name: 'Alice', blood_group: 'O+' }, function(ok, record) {
 *     if (ok) { /* success *\/ } else { /* error *\/ }
 *   });
 */
(function () {
  'use strict';

  window.MV = window.MV || {};

  /**
   * POST /patient/record with a partial update payload.
   *
   * @param {string}   password - The user's account password (never stored
   *                              in localStorage — only in-memory or
   *                              sessionStorage as a one-shot relay).
   * @param {object}   partial  - Fields to update in the encrypted record.
   * @param {function} onDone   - Callback(ok: bool, record: object|null).
   */
  MV.saveRecord = function (password, partial, onDone) {
    fetch('/patient/record', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: password, update: partial }),
    })
      .then(function (r) {
        return r.json().then(function (d) { return { status: r.status, body: d }; });
      })
      .then(function (res) {
        var d = res.body;
        if (d.error === 'unauthenticated' || res.status === 401) {
          if (typeof onDone === 'function') {
            onDone(false, null, 'Your session expired. Please refresh the page and log in again.');
          }
          return;
        }
        if (d.error) {
          if (typeof onDone === 'function') onDone(false, null, d.error);
          return;
        }
        if (typeof onDone === 'function') onDone(true, d.record || null, null);
      })
      .catch(function (err) {
        if (typeof onDone === 'function') onDone(false, null, 'Network error — please try again.');
      });
  };

  /**
   * POST /patient/onboarding/status
   *
   * @param {string}   status  - 'minimum_done' | 'complete' | 'skipped'
   * @param {function} onDone  - Callback(ok: bool)
   */
  MV.setOnboardingStatus = function (status, onDone) {
    fetch('/patient/onboarding/status', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: status }),
    })
      .then(function (r) {
        return r.json().then(function (d) { return { status: r.status, body: d }; });
      })
      .then(function (res) {
        var d = res.body;
        if (d.error === 'unauthenticated' || res.status === 401) {
          if (typeof onDone === 'function') onDone(false);
          return;
        }
        if (typeof onDone === 'function') onDone(!d.error);
      })
      .catch(function () {
        if (typeof onDone === 'function') onDone(false);
      });
  };

  /**
   * GET /patient/onboarding/status
   *
   * @param {function} onDone - Callback(status: string)
   */
  MV.getOnboardingStatus = function (onDone) {
    fetch('/patient/onboarding/status')
      .then(function (r) {
        return r.json().then(function (d) { return { status: r.status, body: d }; });
      })
      .then(function (res) {
        var d = res.body;
        if (d.error === 'unauthenticated' || res.status === 401) {
          if (typeof onDone === 'function') onDone('pending');
          return;
        }
        if (typeof onDone === 'function') onDone(d.status || 'pending');
      })
      .catch(function () {
        if (typeof onDone === 'function') onDone('pending');
      });
  };
})();
