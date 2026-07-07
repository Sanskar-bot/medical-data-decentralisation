# -*- coding: utf-8 -*-
import os

with open("portals/templates/landing.html", "r", encoding="utf-8") as f:
    content = f.read()

html_old = """            <form id="register-form" novalidate>
              <div class="input-group">
                <label class="input-label" for="reg-name">Full name</label>
                <input class="input-field" type="text" id="reg-name" name="name" autocomplete="name" placeholder="Jane Smith" required>
              </div>
              <div class="input-group">
                <label class="input-label" for="reg-email">Email address</label>
                <input class="input-field" type="email" id="reg-email" name="email" autocomplete="email" placeholder="you@example.com" required>
              </div>
              <div class="input-group">
                <label class="input-label" for="reg-username">Username</label>
                <input class="input-field" type="text" id="reg-username" name="username" autocomplete="username" placeholder="janesmith" required>
                <span class="input-hint">Lowercase letters, numbers, dot, underscore only</span>
              </div>
              <div class="input-group">
                <label class="input-label" for="reg-password">Password</label>
                <input class="input-field" type="password" id="reg-password" name="password" autocomplete="new-password" placeholder="Min. 8 characters" required>
                <span class="input-hint" id="password-strength"></span>
              </div>
              <button class="btn-primary w-full" type="submit" id="register-submit-btn">
                <span id="register-btn-text">Create account</span>
                <span id="register-spinner" class="spinner" style="display:none;"></span>
              </button>
            </form>"""

html_new = """            <div class="auth-tab-switcher" role="tablist" aria-label="Account type" style="margin-bottom:var(--sp-5);">
              <button class="auth-tab active" data-reg-role="patient" role="tab" aria-selected="true" id="reg-tab-patient" type="button">Patient</button>
              <button class="auth-tab" data-reg-role="doctor" role="tab" aria-selected="false" id="reg-tab-doctor" type="button">Doctor</button>
            </div>
            <form id="register-form" novalidate>
              <input type="hidden" id="reg-role" value="patient">
              
              <!-- STEP 1: Details -->
              <div id="reg-step-1">
                <div class="input-group">
                  <label class="input-label" for="reg-name">Full name</label>
                  <input class="input-field" type="text" id="reg-name" name="name" autocomplete="name" placeholder="Jane Smith" required>
                </div>
                <div class="input-group">
                  <label class="input-label" for="reg-phone">Phone number</label>
                  <input class="input-field" type="tel" id="reg-phone" name="phone" autocomplete="tel" placeholder="+1234567890" required>
                </div>
                <div class="input-group">
                  <label class="input-label" for="reg-email">Email address (Optional)</label>
                  <input class="input-field" type="email" id="reg-email" name="email" autocomplete="email" placeholder="you@example.com">
                </div>
                <div class="input-group">
                  <label class="input-label" for="reg-username">Username</label>
                  <input class="input-field" type="text" id="reg-username" name="username" autocomplete="username" placeholder="janesmith" required>
                  <span class="input-hint">Lowercase letters, numbers, dot, underscore only</span>
                </div>
                <div class="input-group">
                  <label class="input-label" for="reg-password">Password</label>
                  <input class="input-field" type="password" id="reg-password" name="password" autocomplete="new-password" placeholder="Min. 8 characters" required>
                  <span class="input-hint" id="password-strength"></span>
                </div>
                <div class="input-group hidden" id="doctor-fields">
                  <label class="input-label" for="reg-specialization">Specialization</label>
                  <input class="input-field" type="text" id="reg-specialization" placeholder="Cardiology">
                  <label class="input-label" for="reg-hospital" style="margin-top:var(--sp-3);">Hospital</label>
                  <input class="input-field" type="text" id="reg-hospital" placeholder="General Hospital">
                </div>
                <button class="btn-primary w-full" type="button" id="register-next-btn">
                  <span id="register-btn-text">Continue</span>
                  <span id="register-spinner" class="spinner" style="display:none;"></span>
                </button>
              </div>

              <!-- STEP 2: Phone Verify -->
              <div id="reg-step-2" class="hidden">
                <button type="button" class="btn-ghost btn-sm" id="reg-back-2" style="margin-bottom:var(--sp-4);">&larr; Back</button>
                <p class="auth-form-sub" style="margin-bottom:var(--sp-4);">We sent an SMS with a code to <span id="display-phone" style="font-weight:600; color:var(--tx1);"></span>.</p>
                <div class="input-group">
                  <label class="input-label" for="reg-phone-otp">SMS Verification Code</label>
                  <input class="input-field" type="text" id="reg-phone-otp" placeholder="Enter 6-digit code">
                </div>
                <button class="btn-primary w-full" type="button" id="register-verify-phone-btn">
                  <span id="phone-verify-btn-text">Verify Phone</span>
                  <span id="phone-verify-spinner" class="spinner" style="display:none;"></span>
                </button>
              </div>

              <!-- STEP 3: Email Verify -->
              <div id="reg-step-3" class="hidden">
                <button type="button" class="btn-ghost btn-sm" id="reg-back-3" style="margin-bottom:var(--sp-4);">&larr; Back</button>
                <p class="auth-form-sub" style="margin-bottom:var(--sp-4);">We sent an email with a code to <span id="display-email" style="font-weight:600; color:var(--tx1);"></span>.</p>
                <div class="input-group">
                  <label class="input-label" for="reg-email-otp">Email Verification Code</label>
                  <input class="input-field" type="text" id="reg-email-otp" placeholder="Enter 6-digit code">
                </div>
                <button class="btn-primary w-full" type="button" id="register-verify-email-btn">
                  <span id="email-verify-btn-text">Verify Email &amp; Create Account</span>
                  <span id="email-verify-spinner" class="spinner" style="display:none;"></span>
                </button>
              </div>
            </form>"""

js_old = """    // -- Register submit -------------------------------------------
    document.getElementById('register-form').addEventListener('submit', function(e) {
      e.preventDefault();
      var btn = document.getElementById('register-submit-btn');
      var alertEl = document.getElementById('register-alert');
      var role     = document.getElementById('reg-role').value;
      var name     = document.getElementById('reg-name').value.trim();
      var email    = document.getElementById('reg-email').value.trim();
      var username = document.getElementById('reg-username').value.trim();
      var password = document.getElementById('reg-password').value;
      var spec     = document.getElementById('reg-specialization').value.trim();
      var hosp     = document.getElementById('reg-hospital').value.trim();

      if (!name || !email || !username || !password) {
        showAlert(alertEl, 'All required fields must be filled in.', 'error');
        return;
      }
      if (password.length < 8) {
        showAlert(alertEl, 'Password must be at least 8 characters.', 'error');
        return;
      }

      btn.disabled = true;
      document.getElementById('register-btn-text').textContent = 'Creating account…';
      document.getElementById('register-spinner').style.display = 'inline-block';

      var endpoint = role === 'doctor' ? '/register/doctor' : '/register/patient';
      var payload  = {name: name, email: email, username: username, password: password};
      if (role === 'doctor') { payload.specialization = spec; payload.hospital = hosp; }

      fetch(endpoint, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
      })
      .then(function(r) { return r.json().then(function(d) { return {ok: r.ok, data: d}; }); })
      .then(function(res) {
        if (res.ok && res.data.redirect) {
          window.location.href = res.data.redirect;
        } else {
          showAlert(alertEl, res.data.error || 'Registration failed. Please try again.', 'error');
          btn.disabled = false;
          document.getElementById('register-btn-text').textContent = 'Create account';
          document.getElementById('register-spinner').style.display = 'none';
        }
      })
      .catch(function() {
        showAlert(alertEl, 'Network error. Please try again.', 'error');
        btn.disabled = false;
        document.getElementById('register-btn-text').textContent = 'Create account';
        document.getElementById('register-spinner').style.display = 'none';
      });
    });"""

js_new = """    // -- Register tabs -------------------------------------------
    document.querySelectorAll('[data-reg-role]').forEach(function(tab) {
      tab.addEventListener('click', function() {
        document.querySelectorAll('[data-reg-role]').forEach(function(t) {
          t.classList.remove('active');
          t.setAttribute('aria-selected', 'false');
        });
        tab.classList.add('active');
        tab.setAttribute('aria-selected', 'true');
        var role = tab.getAttribute('data-reg-role');
        document.getElementById('reg-role').value = role;
        if (role === 'doctor') {
          document.getElementById('doctor-fields').classList.remove('hidden');
        } else {
          document.getElementById('doctor-fields').classList.add('hidden');
        }
      });
    });

    // -- Register submit -------------------------------------------
    var state = { phone_token: '', email_token: '' };

    function getRegPayload() {
      var role = document.getElementById('reg-role').value;
      var data = {
        role: role,
        name: document.getElementById('reg-name').value.trim(),
        email: document.getElementById('reg-email').value.trim(),
        phone: document.getElementById('reg-phone').value.trim(),
        username: document.getElementById('reg-username').value.trim(),
        password: document.getElementById('reg-password').value
      };
      if (role === 'doctor') {
        data.specialization = document.getElementById('reg-specialization').value.trim();
        data.hospital = document.getElementById('reg-hospital').value.trim();
      }
      return data;
    }

    // Step 1: Send SMS
    document.getElementById('register-next-btn').addEventListener('click', function() {
      var alertEl = document.getElementById('register-alert');
      alertEl.style.display = 'none';
      var d = getRegPayload();
      if (!d.name || !d.phone || !d.username || !d.password) {
        showAlert(alertEl, 'Name, Phone, Username, and Password are required.', 'error');
        return;
      }
      if (d.password.length < 8) {
        showAlert(alertEl, 'Password must be at least 8 characters.', 'error');
        return;
      }

      var btn = document.getElementById('register-next-btn');
      btn.disabled = true;
      document.getElementById('register-btn-text').textContent = 'Sending SMS…';
      document.getElementById('register-spinner').style.display = 'inline-block';

      fetch('/auth/otp/send_sms', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({phone: d.phone})
      })
      .then(function(r) { return r.json().then(function(data) { return {ok: r.ok, data: data}; }); })
      .then(function(res) {
        btn.disabled = false;
        document.getElementById('register-btn-text').textContent = 'Continue';
        document.getElementById('register-spinner').style.display = 'none';
        
        if (res.ok) {
          document.getElementById('display-phone').textContent = d.phone;
          document.getElementById('reg-step-1').classList.add('hidden');
          document.getElementById('reg-step-2').classList.remove('hidden');
        } else {
          showAlert(alertEl, res.data.error || 'Failed to send SMS.', 'error');
        }
      })
      .catch(function() {
        btn.disabled = false;
        document.getElementById('register-btn-text').textContent = 'Continue';
        document.getElementById('register-spinner').style.display = 'none';
        showAlert(alertEl, 'Network error.', 'error');
      });
    });

    // Step 2: Verify SMS
    document.getElementById('register-verify-phone-btn').addEventListener('click', function() {
      var alertEl = document.getElementById('register-alert');
      alertEl.style.display = 'none';
      var otp = document.getElementById('reg-phone-otp').value.trim();
      if (!otp) return showAlert(alertEl, 'Please enter the SMS code.', 'error');
      
      var d = getRegPayload();
      var btn = document.getElementById('register-verify-phone-btn');
      btn.disabled = true;
      document.getElementById('phone-verify-btn-text').textContent = 'Verifying…';
      document.getElementById('phone-verify-spinner').style.display = 'inline-block';

      fetch('/auth/otp/verify_sms', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({phone: d.phone, otp: otp})
      })
      .then(function(r) { return r.json().then(function(data) { return {ok: r.ok, data: data}; }); })
      .then(function(res) {
        btn.disabled = false;
        document.getElementById('phone-verify-btn-text').textContent = 'Verify Phone';
        document.getElementById('phone-verify-spinner').style.display = 'none';

        if (res.ok) {
          state.phone_token = res.data.verification_token;
          if (d.email) {
            // Need email verification, send email OTP
            sendEmailOtp(d.email);
          } else {
            // No email, register directly
            finalRegister();
          }
        } else {
          showAlert(alertEl, res.data.error || 'Invalid SMS code.', 'error');
        }
      })
      .catch(function() {
        btn.disabled = false;
        document.getElementById('phone-verify-btn-text').textContent = 'Verify Phone';
        document.getElementById('phone-verify-spinner').style.display = 'none';
        showAlert(alertEl, 'Network error.', 'error');
      });
    });

    function sendEmailOtp(email) {
      var alertEl = document.getElementById('register-alert');
      alertEl.style.display = 'none';
      
      var btn = document.getElementById('register-verify-phone-btn');
      btn.disabled = true;
      document.getElementById('phone-verify-btn-text').textContent = 'Sending Email…';
      document.getElementById('phone-verify-spinner').style.display = 'inline-block';

      fetch('/auth/otp/send', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email: email})
      })
      .then(function(r) { return r.json().then(function(data) { return {ok: r.ok, data: data}; }); })
      .then(function(res) {
        btn.disabled = false;
        document.getElementById('phone-verify-btn-text').textContent = 'Verify Phone';
        document.getElementById('phone-verify-spinner').style.display = 'none';
        
        if (res.ok) {
          document.getElementById('display-email').textContent = email;
          document.getElementById('reg-step-2').classList.add('hidden');
          document.getElementById('reg-step-3').classList.remove('hidden');
        } else {
          showAlert(alertEl, res.data.error || 'Failed to send Email OTP.', 'error');
        }
      })
      .catch(function() {
        btn.disabled = false;
        document.getElementById('phone-verify-btn-text').textContent = 'Verify Phone';
        document.getElementById('phone-verify-spinner').style.display = 'none';
        showAlert(alertEl, 'Network error.', 'error');
      });
    }

    // Step 3: Verify Email
    document.getElementById('register-verify-email-btn').addEventListener('click', function() {
      var alertEl = document.getElementById('register-alert');
      alertEl.style.display = 'none';
      var otp = document.getElementById('reg-email-otp').value.trim();
      if (!otp) return showAlert(alertEl, 'Please enter the email code.', 'error');
      
      var d = getRegPayload();
      var btn = document.getElementById('register-verify-email-btn');
      btn.disabled = true;
      document.getElementById('email-verify-btn-text').textContent = 'Verifying…';
      document.getElementById('email-verify-spinner').style.display = 'inline-block';

      fetch('/auth/otp/verify', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email: d.email, otp: otp})
      })
      .then(function(r) { return r.json().then(function(data) { return {ok: r.ok, data: data}; }); })
      .then(function(res) {
        btn.disabled = false;
        document.getElementById('email-verify-btn-text').textContent = 'Verify Email & Create Account';
        document.getElementById('email-verify-spinner').style.display = 'none';

        if (res.ok) {
          state.email_token = res.data.verification_token;
          finalRegister();
        } else {
          showAlert(alertEl, res.data.error || 'Invalid Email code.', 'error');
        }
      })
      .catch(function() {
        btn.disabled = false;
        document.getElementById('email-verify-btn-text').textContent = 'Verify Email & Create Account';
        document.getElementById('email-verify-spinner').style.display = 'none';
        showAlert(alertEl, 'Network error.', 'error');
      });
    });

    // Final Register Call
    function finalRegister() {
      var alertEl = document.getElementById('register-alert');
      alertEl.style.display = 'none';
      
      var d = getRegPayload();
      d.phone_verification_token = state.phone_token;
      d.email_verification_token = state.email_token;

      fetch('/auth/register', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(d)
      })
      .then(function(r) { return r.json().then(function(data) { return {ok: r.ok, data: data}; }); })
      .then(function(res) {
        if (res.ok && res.data.redirect) {
          window.location.href = res.data.redirect;
        } else {
          showAlert(alertEl, res.data.error || 'Registration failed.', 'error');
        }
      })
      .catch(function() {
        showAlert(alertEl, 'Network error during final registration.', 'error');
      });
    }

    // Back buttons
    document.getElementById('reg-back-2').addEventListener('click', function() {
      document.getElementById('reg-step-2').classList.add('hidden');
      document.getElementById('reg-step-1').classList.remove('hidden');
      document.getElementById('register-alert').style.display = 'none';
    });
    document.getElementById('reg-back-3').addEventListener('click', function() {
      document.getElementById('reg-step-3').classList.add('hidden');
      document.getElementById('reg-step-2').classList.remove('hidden');
      document.getElementById('register-alert').style.display = 'none';
    });
"""

if html_old not in content:
    print("HTML OLD NOT FOUND!")
else:
    content = content.replace(html_old, html_new)

if js_old not in content:
    print("JS OLD NOT FOUND!")
else:
    content = content.replace(js_old, js_new)

with open("portals/templates/landing.html", "w", encoding="utf-8") as f:
    f.write(content)

print("Replacement Complete.")
