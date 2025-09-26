// background.js - minimal; used for notifications
chrome.runtime.onMessage.addListener((message, sender) => {
  if (message.type === 'notify') {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'phish.png',
      title: message.title || 'Phishing Detector',
      message: message.message || ''
    });
  }
});
