// content.js
// Watches input fields for URLs, calls local model server to get prediction,
// and shows an inline badge next to input showing status.

const createBadge = (text, color) => {
  const badge = document.createElement('div');
  badge.className = 'phish-badge';
  badge.textContent = text;
  badge.style.position = 'absolute';
  badge.style.zIndex = 2147483647;
  badge.style.padding = '4px 8px';
  badge.style.borderRadius = '12px';
  badge.style.fontSize = '12px';
  badge.style.background = color;
  badge.style.color = 'white';
  badge.style.boxShadow = '0 1px 4px rgba(0,0,0,0.3)';
  return badge;
};

const styleBadgeIfMissing = () => {
  if (!document.getElementById('phish-ext-style')) {
    const s = document.createElement('style');
    s.id = 'phish-ext-style';
    s.textContent = `
      .phish-badge { pointer-events: none; }
    `;
    document.head.appendChild(s);
  }
};
styleBadgeIfMissing();

const DEBOUNCE_MS = 700;
let timers = new WeakMap();

function getServerUrl() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['serverUrl'], (res) => {
      resolve(res.serverUrl || 'http://localhost:5000');
    });
  });
}

async function checkUrlWithServer(url) {
  try {
    const server = await getServerUrl();
    const resp = await fetch(server.replace(/\/$/, '') + '/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    if (!resp.ok) throw new Error('Server error ' + resp.status);
    return await resp.json();
  } catch (err) {
    console.error('PhishExt: fetch error', err);
    return { error: String(err) };
  }
}

function attachBadgeToInput(input) {
  if (input._phishBadgeAttached) return;
  input._phishBadgeAttached = true;

  const wrapper = document.createElement('div');
  wrapper.style.position = 'relative';
  wrapper.style.display = 'inline-block';

  // wrap input with wrapper to allow absolute positioning
  input.parentNode.insertBefore(wrapper, input);
  wrapper.appendChild(input);

  const badge = createBadge('Checking...', '#999');
  wrapper.appendChild(badge);
  badge.style.display = 'none';

  function positionBadge() {
    // position top-right
    badge.style.display = '';
    badge.style.top = (input.offsetTop + 4) + 'px';
    badge.style.right = (wrapper.offsetWidth - input.clientWidth - input.offsetLeft + 4) + 'px';
  }

  async function onInput() {
    clearTimeout(timers.get(input));
    timers.set(input, setTimeout(async () => {
      const value = input.value.trim();
      if (!value || value.length < 3 || (!value.includes('.') && !value.startsWith('http'))) {
        badge.style.display = 'none';
        return;
      }
      badge.textContent = 'Checking...';
      badge.style.background = '#999';
      badge.style.display = '';

      const result = await checkUrlWithServer(value);
      if (result.error) {
        badge.textContent = 'Server error';
        badge.style.background = '#666';
        return;
      }
      // expected result: { label: 'phishing'|'legit', score: 0.92 }
      const label = result.label || (result.prediction ? result.prediction : 'unknown');
      const score = (typeof result.score === 'number') ? result.score : (result.confidence || null);

      if (label.toLowerCase() === 'phishing' || label.toLowerCase() === 'malicious') {
        badge.textContent = `Phishing (${(score ? (score*100).toFixed(0) : '?')}%)`;
        badge.style.background = '#D32F2F';
        // also send a desktop notification
        chrome.runtime.sendMessage({
          type: 'notify',
          title: 'Potential phishing detected',
          message: value
        });
      } else {
        badge.textContent = `Safe (${(score ? (score*100).toFixed(0) : '?')}%)`;
        badge.style.background = '#388E3C';
      }
      positionBadge();
    }, DEBOUNCE_MS));
  }

  // initial position and reposition on resize/scroll
  const resizeObserver = new ResizeObserver(positionBadge);
  resizeObserver.observe(input);

  input.addEventListener('input', onInput);
  input.addEventListener('blur', () => { setTimeout(() => badge.style.display='none', 500); });
  input.addEventListener('focus', positionBadge);
}

function scanAndAttach() {
  // target typical URL input types
  const selectors = 'input[type=url], input[type=text], textarea, input[placeholder*="url"], input[placeholder*="URL"], input[id*="url"], input[name*="url"]';
  const inputs = document.querySelectorAll(selectors);
  inputs.forEach(el => attachBadgeToInput(el));
}

// initial scan
scanAndAttach();

// observe DOM for dynamically added inputs
const observer = new MutationObserver((mutations) => {
  scanAndAttach();
});
observer.observe(document.documentElement || document.body, { childList: true, subtree: true });
