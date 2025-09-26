document.addEventListener('DOMContentLoaded', () => {
  const serverUrlInput = document.getElementById('serverUrl');
  const saveBtn = document.getElementById('save');
  const status = document.getElementById('status');

  // load saved server url
  chrome.storage.local.get(['serverUrl'], (res) => {
    if (res.serverUrl) serverUrlInput.value = res.serverUrl;
  });

  saveBtn.addEventListener('click', () => {
    const url = serverUrlInput.value.trim();
    if (!url) {
      status.textContent = 'Please enter a server URL.';
      return;
    }
    chrome.storage.local.set({ serverUrl: url }, () => {
      status.textContent = 'Saved!';
      setTimeout(() => status.textContent = '', 1500);
    });
  });
});
