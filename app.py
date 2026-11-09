import sqlite3
from pathlib import Path
import socket
import re
import streamlit as st
import pandas as pd
import ipaddress

from urllib.parse import urlparse
from datetime import datetime


# -------------------------------
# 1. PAGE CONFIGURATION
# -------------------------------

st.set_page_config(
    page_title="PhishGuard | URL Analyzer",
    page_icon="🛡️",
    layout="wide"
)


# -------------------------------
# DATABASE CONFIGURATION
# -------------------------------

DB_PATH = Path(__file__).resolve().parent / "phishguard.db"


def init_database():

    connection = sqlite3.connect(DB_PATH)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date_time TEXT,
            url TEXT,
            domain TEXT,
            risk_score INTEGER,
            risk_level TEXT
        )
    """)

    connection.commit()
    connection.close()


init_database()
# -------------------------------
# DATABASE FUNCTIONS
# -------------------------------

def save_scan(url, domain, score, risk_level):

    connection = sqlite3.connect(DB_PATH)

    connection.execute("""
        INSERT INTO scan_history
        (date_time, url, domain, risk_score, risk_level)
        VALUES (?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        url,
        domain,
        score,
        risk_level
    ))

    connection.commit()
    connection.close()


def get_scan_history():

    connection = sqlite3.connect(DB_PATH)

    history = pd.read_sql_query("""
        SELECT
            date_time AS 'Date & Time',
            url AS 'URL',
            domain AS 'Domain',
            risk_score AS 'Risk Score',
            risk_level AS 'Risk Level'
        FROM scan_history
        ORDER BY id DESC
    """, connection)

    connection.close()

    return history


def clear_scan_history():

    connection = sqlite3.connect(DB_PATH)

    connection.execute("DELETE FROM scan_history")

    connection.commit()
    connection.close()

# -------------------------------
# 3. URL ANALYSIS FUNCTION
# -------------------------------

def analyze_url(url):

    url = url.strip()

    # Add HTTPS if the user does not enter a scheme
    if "://" not in url:
        url = "https://" + url

    warnings = []
    risk_score = 0

    try:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
    except ValueError:
        return "Unknown", 0, ["Invalid URL format"], "Invalid URL"

    # Check URL scheme
    if parsed.scheme not in ["http", "https"]:
        return domain or "Unknown", 0, ["Invalid URL scheme"], "Invalid URL"

    if not domain:
        return "Unknown", 0, ["Domain not found in URL"], "Invalid URL"

    # Check port format
    try:
        parsed.port
    except ValueError:
        return domain, 0, ["Invalid port number"], "Invalid URL"

    # Check IP address
    try:
        ipaddress.ip_address(domain)
        is_ip = True
    except ValueError:
        is_ip = False

    # Validate domain format
    if not is_ip:

        labels = domain.split(".")

        valid_domain = (
            len(domain) <= 253
            and len(labels) >= 2
            and all(
                1 <= len(label) <= 63
                and re.fullmatch(r"[a-zA-Z0-9-]+", label)
                and not label.startswith("-")
                and not label.endswith("-")
                for label in labels
            )
        )

        if not valid_domain:
            return domain, 0, ["Invalid domain format"], "Invalid URL"

        # DNS lookup
        try:
            socket.getaddrinfo(domain, None)

        except socket.gaierror:
            return (
                domain,
                0,
                ["Domain could not be resolved through DNS"],
                "Domain not found"
            )

        except OSError:
            return (
                domain,
                0,
                ["DNS lookup could not be completed"],
                "DNS Error"
            )

    # HTTPS check
    if parsed.scheme != "https":
        warnings.append("Website does not use HTTPS")
        risk_score += 1

    # IP address check
    if is_ip:
        warnings.append("URL uses an IP address instead of a domain")
        risk_score += 3

    # Check @ symbol in URL authority
    if "@" in parsed.netloc:
        warnings.append("URL contains an @ symbol")
        risk_score += 2

    # URL shortener check
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd"
    ]

    normalized_domain = domain.lower().removeprefix("www.")

    if normalized_domain in shorteners:
        warnings.append("URL uses a known URL shortener")
        risk_score += 2

    # Suspicious keyword check
    suspicious_words = [
        "login",
        "verify",
        "password",
        "account",
        "update",
        "banking"
    ]

    for word in suspicious_words:
        if word in url.lower():
            warnings.append(f"Potentially suspicious keyword: {word}")
            risk_score += 1

    # Risk classification
    if risk_score >= 4:
        risk_level = "High"
    elif risk_score >= 2:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return domain, risk_score, warnings, risk_level


# -------------------------------
# 4. APPLICATION HEADER
# -------------------------------

st.title("🛡️ PhishGuard")

st.caption(
    "Phishing URL Detection & Cybersecurity Awareness Tool"
)

st.markdown("---")


# -------------------------------
# 5. URL ANALYZER
# -------------------------------

st.header("🔍 URL Security Scanner")

url_input = st.text_input(
    "Enter a URL to analyse:",
    placeholder="https://example.com"
)

if st.button("Analyse URL", type="primary"):

    if not url_input.strip():

        st.warning("Please enter a URL first.")

    else:

        domain, score, warnings, risk_level = analyze_url(url_input)

        # Display result
        st.subheader("Scan Result")

        st.write("**Domain:**", domain)
        st.write("**Risk Score:**", score)

        if risk_level == "High":
            st.error("High Risk")

        elif risk_level == "Medium":
            st.warning("Medium Risk")

        elif risk_level == "Low":
            st.success("Low Risk")

        else:
            st.info(risk_level)

        if warnings:
            st.write("**Warnings:**")

            for warning in warnings:
                st.write("⚠️", warning)

        else:
            st.write("No warning rules were triggered.")

        # Save scan to history
        save_scan(
    url_input.strip(),
    domain,
    score,
    risk_level
)


st.markdown("---")


# -------------------------------
# DASHBOARD METRICS
# -------------------------------

history_df = get_scan_history()
if not history_df.empty:

    csv_data = history_df.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="📥 Download Scan Report",
        data=csv_data,
        file_name="phishguard_scan_report.csv",
        mime="text/csv"
    )
total_scans = len(history_df)

high_scans = (
    history_df["Risk Level"] == "High"
).sum()

medium_scans = (
    history_df["Risk Level"] == "Medium"
).sum()

low_scans = (
    history_df["Risk Level"] == "Low"
).sum()

invalid_scans = history_df["Risk Level"].isin([
    "Invalid URL",
    "Domain not found",
    "DNS Error"
]).sum()

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Total Scans", total_scans)
col2.metric("High Risk", int(high_scans))
col3.metric("Medium Risk", int(medium_scans))
col4.metric("Low Risk", int(low_scans))
col5.metric("Invalid / Unresolved", int(invalid_scans))


st.markdown("---")


# -------------------------------
# SCAN HISTORY
# -------------------------------

st.header("📋 Scan History")

if not history_df.empty:

    st.dataframe(
        history_df,
        use_container_width=True,
        hide_index=True
    )

    if st.button("Clear Scan History"):

        clear_scan_history()

        st.success("Scan history cleared.")

        st.rerun()

else:

    st.info("No URLs have been analysed yet.")
# -------------------------------
# 8. DISCLAIMER
# -------------------------------

st.markdown("---")

st.caption(
    "Disclaimer: PhishGuard is an educational, rule-based "
    "URL screening tool. It does not guarantee that a "
    "website is safe or malicious. DNS resolution only "
    "checks whether a domain can be resolved. HTTPS alone "
    "does not establish website trustworthiness. "
    "This tool does not verify website content."
)
