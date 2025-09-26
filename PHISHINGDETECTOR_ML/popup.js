document.getElementById('detectBtn').addEventListener('click', async () => {
    const url = document.getElementById('urlInput').value.trim();
    const resultDiv = document.getElementById('result');
    resultDiv.innerHTML = '<span style="font-size:1.2em;">Checking...</span>';

    if (!url) {
        resultDiv.innerHTML = '<span style="font-size:1.2em;color:#d32f2f;">Please enter a URL.</span>';
        return;
    }

    try {
        const response = await fetch('http://127.0.0.1:5000/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        if (response.ok) {
            const score = data.score !== null ? data.score.toFixed(2) : "N/A";
            let verdictColor = data.verdict === "PHISHING" ? "#d32f2f" : "#1976d2";
            let verdictEmoji = data.verdict === "PHISHING" ? "❌" : "✅";
            resultDiv.innerHTML = `
                <div style="font-size:2em;font-weight:bold;color:${verdictColor};margin-bottom:8px;">
                    ${verdictEmoji} ${data.verdict_text}
                </div>
                <div style="font-size:1.3em;color:#333;">
                    Phishing Probability: <b>${score}</b>
                </div>
            `;
        } else {
            resultDiv.innerHTML = `<span style="font-size:1.2em;color:#d32f2f;">${data.error || 'Error occurred.'}</span>`;
        }
    } catch (err) {
        resultDiv.innerHTML = '<span style="font-size:1.2em;color:#d32f2f;">Could not connect to server.</span>';
    }
});