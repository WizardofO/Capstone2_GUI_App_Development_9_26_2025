///MOIT-200 CAPSTONE2_TITLE: Signature-Based Analysis of Open-Source Phishing Toolkits for Machine Learning-Based Detection "A Case Study Using BlackEye and Zphisher and other sites"
///Author: Osias Nieva 
const summaryBtn = document.getElementById('summaryBtn');
summaryBtn.disabled = true;

let lastDetailedReport = null;
let lastVerdict = null;
let lastScore = null;
let lastVerdictText = null;
let lastCheckedUrl = null;
let lastReportDate = null; // store date/time

// ----------------------------
// Detect button logic
// ----------------------------
document.getElementById('detectBtn').addEventListener('click', async () => {
    const url = document.getElementById('urlInput').value.trim();
    const resultDiv = document.getElementById('result');
    resultDiv.innerHTML = '<span style="font-size:1.2em;">Checking...</span>';

    if (!url) {
        resultDiv.innerHTML = '<span style="font-size:1.2em;color:#d32f2f;">Please enter a URL.</span>';
        return;
    }

    lastCheckedUrl = url;
    lastReportDate = new Date().toLocaleString();

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
            let verdictIcon = data.verdict_icon || (data.verdict === "PHISHING" ? "❌" : "✔️");
            resultDiv.innerHTML = `
                <div style="font-size:2.6em;font-weight:bold;color:${verdictColor};margin-bottom:8px;">
                    ${verdictIcon} <span style="font-size:1.1em;">${data.verdict_text}</span>
                </div>
                <div style="font-size:1.5em;color:#333;">
                    Phishing Probability: <b>${score}</b>
                </div>
            `;
            lastVerdict = data.verdict || null;
            lastScore = data.score !== null ? data.score : null;
            lastVerdictText = data.verdict_text || null;

            try {
                const summaryResp = await fetch('http://127.0.0.1:5000/summary_report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url })
                });
                const summaryData = await summaryResp.json();
                if (summaryResp.ok && summaryData.summary_report && Array.isArray(summaryData.summary_report)) {
                    lastDetailedReport = summaryData.summary_report;
                    showSummaryReport(lastDetailedReport, lastVerdict, lastScore, lastVerdictText);
                } else {
                    lastDetailedReport = null;
                    showSummaryReport(null);
                }
            } catch (e) {
                lastDetailedReport = null;
                showSummaryReport(null);
            }
            summaryBtn.disabled = false;
        } else {
            summaryBtn.disabled = true;
            resultDiv.innerHTML = `<span style="font-size:1.2em;color:#d32f2f;">${data.error || 'Error occurred.'}</span>`;
            showSummaryReport(null);
        }
    } catch (err) {
        summaryBtn.disabled = true;
        resultDiv.innerHTML = '<span style="font-size:1.2em;color:#d32f2f;">Could not connect to server.</span>';
        showSummaryReport(null);
    }
});

// ----------------------------
// Summary modal logic
// ----------------------------
summaryBtn.addEventListener('click', () => {
    const modal = document.getElementById('summaryModal');
    const content = document.getElementById('summaryContent');

    if (lastDetailedReport && Array.isArray(lastDetailedReport)) {
        renderSummaryModal(content);
        modal.style.display = 'flex';
        return;
    }
    content.innerHTML = '<b>No summary available. Please run detection first.</b>';
    modal.style.display = 'flex';
});

// Close modal
document.getElementById('closeSummary').addEventListener('click', () => {
    document.getElementById('summaryModal').style.display = 'none';
});
document.getElementById('summaryModal').addEventListener('click', (e) => {
    if (e.target === document.getElementById('summaryModal')) {
        document.getElementById('summaryModal').style.display = 'none';
    }
});

// ----------------------------
// Export buttons
// ----------------------------
document.getElementById('saveSummaryBtn').addEventListener('click', function() {
    if (!lastDetailedReport || !Array.isArray(lastDetailedReport)) return;
    let text = 'Signature_Based Detection Summary Report\n\n';
    text += `URL: ${lastCheckedUrl || "N/A"}\n`;
    text += `Date: ${lastReportDate || "N/A"}\n`;
    text += `Verdict: ${lastVerdictText || lastVerdict}\n`;
    text += `Score: ${lastScore !== null ? lastScore.toFixed(2) : "N/A"}\n\n`;
    lastDetailedReport.forEach(f => {
        text += `${f.feature}: ${f.value} - ${f.explanation}\n`;
    });
    text += `\n© 2025-2026_MMDC_Capstone2_NIEVA OSIAS JR©`;
    let blob = new Blob([text], {type: 'text/plain'});
    let a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'phishing_summary_report.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
});

document.getElementById('exportSummaryCSV').addEventListener('click', function() {
    if (!lastDetailedReport || !Array.isArray(lastDetailedReport)) return;
    let csv = `URL,${lastCheckedUrl || "N/A"}\n`;
    csv += `Date,${lastReportDate || "N/A"}\n`;
    csv += `Verdict,${lastVerdictText || lastVerdict}\n`;
    csv += `Score,${lastScore !== null ? lastScore.toFixed(2) : "N/A"}\n\n`;
    csv += 'Feature,Value,Explanation\n';
    lastDetailedReport.forEach(f => {
        csv += `"${f.feature}","${f.value}","${f.explanation.replace(/"/g, '""')}"\n`;
    });
    csv += `\n© 2025-2026_MMDC_Capstone2_NIEVA OSIAS JR©`;
    let blob = new Blob([csv], {type: 'text/csv'});
    let a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'phishing_summary_report.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
});

document.getElementById('exportSummaryPDF').addEventListener('click', function() {
    if (!lastDetailedReport || !Array.isArray(lastDetailedReport)) return;
    let win = window.open('', '', 'width=700,height=900');
    let html = `<html><head><title>Signature_Based Detection Summary Report</title>` +
        `<style>body{font-family:Arial,sans-serif;background:#f5faff;margin:0;padding:24px;}h2{color:#1976d2;}ul{padding-left:20px;}li{margin-bottom:8px;}b{color:#1976d2;} .score{color:#d32f2f;font-weight:bold;} .verdict{font-weight:bold;}</style></head><body>`;
    html += `<h2>Phishing Summary Report</h2>`;
    html += `<div><b>URL:</b> ${lastCheckedUrl || "N/A"}</div>`;
    html += `<div><b>Date:</b> ${lastReportDate || "N/A"}</div>`;
    html += `<div><b>Verdict:</b> <span class='verdict' style='color:${lastVerdict === "PHISHING" ? "#d32f2f" : "#1976d2"};'>${lastVerdictText || lastVerdict}</span></div>`;
    html += `<div><b>Score:</b> <span class='score'>${lastScore !== null ? lastScore.toFixed(2) : "N/A"}</span></div><br/>`;
    html += `<div><b>Key Features:</b></div><ul>`;
    let important = lastDetailedReport.filter(f => f.value && f.value !== 0);
    if (important.length === 0) important = lastDetailedReport.slice(0, 5);
    for (const f of important) {
        html += `<li><b>${f.feature}</b>: ${f.explanation} <span style='color:#1976d2;font-weight:bold;'>[value: ${f.value}]</span></li>`;
    }
    html += `</ul><br/><div><b>All Features:</b></div><ul>`;
    for (const f of lastDetailedReport) {
        html += `<li><b>${f.feature}</b>: ${f.explanation} <span style='color:#1976d2;font-weight:bold;'>[value: ${f.value}]</span></li>`;
    }
    html += `</ul><br/><div style="margin-top:20px;font-size:0.9em;color:#555;">© 2025-2026_MMDC_Capstone2_NIEVA OSIAS JR©</div>`;
    html += `</body></html>`;
    win.document.write(html);
    win.document.close();
    setTimeout(() => { win.print(); }, 500);
});

// ----------------------------
// Report Issue Button and Modal Logic
// ----------------------------
const reportBtn = document.getElementById('reportIssueBtn');
const reportModal = document.getElementById('reportIssueModal');
const closeReportModal = document.getElementById('closeReportModal');
const reportForm = document.getElementById('reportForm');
const reportStatus = document.getElementById('reportStatus');

// Show modal
reportBtn.addEventListener('click', () => {
    reportModal.style.display = 'flex';
    reportStatus.textContent = '';
    reportForm.reset();
});

// Hide modal
closeReportModal.addEventListener('click', () => {
    reportModal.style.display = 'none';
});
reportModal.addEventListener('click', (e) => {
    if (e.target === reportModal) {
        reportModal.style.display = 'none';
    }
});

// Handle form submit
reportForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    reportStatus.textContent = 'Sending...';

    const name = document.getElementById('reportName').value.trim();
    const email = document.getElementById('reportEmail').value.trim();
    const message = document.getElementById('reportMessage').value.trim();
    const screenshotFile = document.getElementById('reportScreenshot').files[0];

    // Prepare form data
    const formData = new FormData();
    formData.append('name', name);
    formData.append('email', email);
    formData.append('message', message);
    if (screenshotFile) {
        formData.append('screenshot', screenshotFile);
    }

    // You need a backend endpoint to receive this report, e.g. /report_issue
    try {
        const response = await fetch('http://localhost:5000/report_issue', {
            method: 'POST',
            body: formData
        });
        if (response.ok) {
            reportStatus.textContent = 'Report submitted successfully!';
            setTimeout(() => { reportModal.style.display = 'none'; }, 1500);
        } else {
            reportStatus.textContent = 'Failed to submit report.';
        }
    } catch (err) {
        reportStatus.textContent = 'Error sending report.';
    }
});

// ----------------------------
// Helper functions
// ----------------------------
function renderSummaryModal(content) {
    let important = lastDetailedReport.filter(f => f.value && f.value !== 0);
    if (important.length === 0) {
        important = lastDetailedReport.slice(0, 5);
    }
    let summaryHtml = `<div style='font-size:1.2em;font-weight:bold;color:#1976d2;margin-bottom:8px;'>SUMMARY REPORT</div>`;
    summaryHtml += `<div><b>URL:</b> ${lastCheckedUrl || "N/A"}</div>`;
    summaryHtml += `<div><b>Date:</b> ${lastReportDate || "N/A"}</div>`;
    summaryHtml += `<div style='margin-bottom:8px;font-size:1.1em;'>This site is <b style='color:${lastVerdict === "PHISHING" ? "#d32f2f" : "#1976d2"};'>${lastVerdictText || lastVerdict}</b> (score: <b>${lastScore !== null ? lastScore.toFixed(2) : "N/A"}</b>).</div>`;
    summaryHtml += `<div style='font-size:1em;margin-bottom:8px;'>Key features that contributed to this result:</div>`;
    summaryHtml += '<ul style="padding-left:18px;">';
    for (const f of important) {
        summaryHtml += `<li><b>${f.feature}</b>: ${f.explanation} <span style='color:#1976d2;font-weight:bold;'>[value: ${f.value}]</span></li>`;
    }
    summaryHtml += '</ul>';
    summaryHtml += `<div style="margin-top:12px;font-size:0.85em;color:#555;">© 2025-2026_MMDC_Capstone2_NIEVA OSIAS JR</div>`;
    content.innerHTML = summaryHtml;
}

function showSummaryReport(report, verdict, score, verdictText) {
    const container = document.getElementById('summaryReportContainer');
    const contentDiv = document.getElementById('summaryReportContent');
    if (!report || !Array.isArray(report)) {
        container.style.display = 'none';
        return;
    }
    let important = report.filter(f => f.value && f.value !== 0);
    if (important.length === 0) {
        important = report.slice(0, 5);
    }
    let html = `<div><b>URL:</b> ${lastCheckedUrl || "N/A"}</div>`;
    html += `<div><b>Date:</b> ${lastReportDate || "N/A"}</div>`;
    html += `<div style='margin-bottom:8px;'>This site is <b style='color:${verdict === "PHISHING" ? "#d32f2f" : "#1976d2"};'>${verdictText || verdict}</b> (score: <b>${score !== null ? score.toFixed(2) : "N/A"}</b>).</div>`;
    html += `<div style='font-size:1em;margin-bottom:8px;'>Key features that contributed to this result:</div>`;
    html += '<ul style="padding-left:18px;">';
    for (const f of important) {
        html += `<li><b>${f.feature}</b>: ${f.explanation} <span style='color:#1976d2;font-weight:bold;'>[value: ${f.value}]</span></li>`;
    }
    html += '</ul>';
    html += `<div style="margin-top:12px;font-size:0.85em;color:#555;">© 2025-2026_MMDC_Capstone2_NIEVA OSIAS JR</div>`;
    contentDiv.innerHTML = html;
    container.style.display = 'block';
}

