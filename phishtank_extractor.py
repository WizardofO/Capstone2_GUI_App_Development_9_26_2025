#!/usr/bin/env python3
"""
phishtank_scraper.py

Scrape phishtank.org phish_archive.php pages and extract rows that appear "valid/online".
Saves output to CSV with columns: phish_id, url, submitted, online, detail_url

Usage:
    python phishtank_scraper.py

Config:
    - MAX_PAGES: how many archive pages to scan (None = auto-discover/paginate until done)
    - delay_seconds: polite delay between page requests
"""

import requests
from bs4 import BeautifulSoup
import time
import csv
import re
import sys
from urllib.parse import urljoin

BASE = "https://phishtank.org"
ARCHIVE = "/phish_archive.php"

HEADERS = {
    "User-Agent": "PhishTankScraper/1.0 (+https://example.com) - for research",
    # add Accept-Language etc. if you want
}

# Config
MAX_PAGES = None        # None => try to follow pagination until there's no next page
DELAY_SECONDS = 1.0     # polite delay between requests (increase if you like)
OUTPUT_CSV = "phishtank_valid_phish_urls.csv"

# Keywords that indicate a row is valid/online. Adjust if phishtank uses different words.
VALID_KEYWORDS = {"valid", "online", "yes", "true", "active"}

session = requests.Session()
session.headers.update(HEADERS)


def get_soup(url):
    try:
        r = session.get(url, timeout=20)
        r.raise_for_status()
        return BeautifulSoup(r.text, "html.parser")
    except Exception as e:
        print(f"[ERROR] Failed to GET {url}: {e}", file=sys.stderr)
        return None


def parse_archive_page(soup):
    """
    Parse phish_archive.php page soup and extract row entries.
    Returns list of dicts: {phish_id, url, submitted, online_text, detail_url}
    """
    rows_out = []

    # Find the main table. There may be a table with class/id; fallback to first big table.
    # We'll search for rows that contain a phish_id or link to phish_detail.php
    table = None
    # heuristic: look for table containing 'phish_id' or column headers
    for t in soup.find_all("table"):
        txt = (t.get_text(" ", strip=True) or "").lower()
        if "phish id" in txt or "phish_id" in txt or "phish id" in txt:
            table = t
            break
    if table is None:
        # fallback: pick the largest table on the page
        tables = soup.find_all("table")
        if tables:
            table = max(tables, key=lambda t: len(t.find_all("tr")))
    if table is None:
        return rows_out

    # iterate rows
    for tr in table.find_all("tr"):
        tds = tr.find_all("td")
        if not tds or len(tds) < 2:
            continue

        # Attempt to find a detail link (phish_detail.php?phish_id=)
        detail_a = tr.find("a", href=re.compile(r"phish_detail\.php\?phish_id=\d+"))
        detail_url = None
        phish_id = None
        if detail_a:
            detail_url = urljoin(BASE, detail_a.get("href"))
            m = re.search(r"phish_id=(\d+)", detail_a.get("href"))
            if m:
                phish_id = m.group(1)

        # Attempt to find the URL cell - look for an anchor with http(s)
        url_candidate = None
        for a in tr.find_all("a", href=True):
            href = a.get("href").strip()
            if href.lower().startswith("http"):
                url_candidate = href
                break

        # Fallback: look into text of first or second td for a URL-looking string
        if not url_candidate:
            for td in tds[:3]:
                text = td.get_text(" ", strip=True)
                m = re.search(r"https?://[^\s'\"<>]+", text)
                if m:
                    url_candidate = m.group(0)
                    break

        # Try to extract submitted date and online/status column if available
        submitted = ""
        online_text = ""
        # Many archive tables have columns like: URL | Phish ID | Submitted | Online? | Verified?
        # We'll heuristically use positions if phish_id is known
        try:
            # find text cells stripped
            cells_text = [td.get_text(" ", strip=True) for td in tds]
            # common patterns:
            # if one of the cells contains 'online' or 'valid' use that
            for ct in cells_text:
                low = ct.lower()
                if any(k in low for k in ["online", "valid", "yes", "active"]):
                    online_text = ct
                    break
            # submitted date is often a date-like cell (contains 4-digit year)
            for ct in cells_text:
                if re.search(r"\b20\d{2}\b", ct):
                    submitted = ct
                    break
        except Exception:
            pass

        if not url_candidate and not detail_url:
            continue

        rows_out.append({
            "phish_id": phish_id or "",
            "url": url_candidate or "",
            "submitted": submitted,
            "online_text": online_text,
            "detail_url": detail_url or ""
        })

    return rows_out


def row_is_valid_online(row):
    """
    Decide if a parsed row indicates a valid phish URL.
    We check the online_text and detail_url page (if available) for keywords.
    """
    # Quick check in the online_text
    ot = (row.get("online_text") or "").lower()
    if any(k in ot for k in VALID_KEYWORDS):
        return True
    # If there's a detail_url, fetch it and inspect for explicit "valid" markers
    if row.get("detail_url"):
        soup = get_soup(row["detail_url"])
        if not soup:
            return False
        text = soup.get_text(" ", strip=True).lower()
        if any(k in text for k in ["valid", "online", "phish confirmed", "verified"]):
            return True
    return False


def find_next_page(soup):
    """
    Look for a pagination link (Next, » or similar) and return the absolute URL or None.
    """
    # Try anchor with rel=next
    a = soup.find("a", rel="next")
    if a and a.get("href"):
        return urljoin(BASE, a.get("href"))
    # Try common 'next' text
    for a in soup.find_all("a", href=True):
        txt = a.get_text(" ", strip=True).lower()
        if txt in ("next", "next »", "»", "›"):
            return urljoin(BASE, a["href"])
    # fallback: None
    return None


def main():
    collected = []
    page_url = urljoin(BASE, ARCHIVE)
    page_count = 0

    print("[*] Starting scrape:", page_url)
    while page_url:
        page_count += 1
        if MAX_PAGES and page_count > MAX_PAGES:
            print("[*] Reached MAX_PAGES limit:", MAX_PAGES)
            break
        print(f"[*] Fetching page {page_count}: {page_url}")
        soup = get_soup(page_url)
        if not soup:
            print("[ERROR] Failed to get page, stopping.")
            break

        rows = parse_archive_page(soup)
        print(f"[*] Parsed {len(rows)} candidate rows on page {page_count}")

        # Check each row for "valid/online"
        for r in rows:
            try:
                if row_is_valid_online(r):
                    collected.append(r)
                    print("[+] Valid:", r.get("url") or r.get("detail_url"))
                else:
                    # skip non-valid
                    pass
            except Exception as e:
                print(f"[!] Error checking row: {e}")

            time.sleep(DELAY_SECONDS)  # polite pause between detail fetches

        # find next page to continue
        next_url = find_next_page(soup)
        if not next_url:
            print("[*] No next page found, stopping pagination.")
            break
        page_url = next_url
        time.sleep(DELAY_SECONDS)

    # Deduplicate by URL (or phish_id if present)
    seen = set()
    unique = []
    for r in collected:
        key = (r.get("phish_id") or r.get("url") or r.get("detail_url")).strip()
        if not key:
            continue
        if key in seen:
            continue
        seen.add(key)
        unique.append(r)

    print(f"[*] Collected {len(unique)} unique valid phish rows. Saving to {OUTPUT_CSV}")

    # Save to CSV
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["phish_id", "url", "submitted", "online_text", "detail_url"])
        writer.writeheader()
        for r in unique:
            writer.writerow(r)

    print("[*] Done.")


if __name__ == "__main__":
    main()
