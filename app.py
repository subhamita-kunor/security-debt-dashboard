"""
Streamlit Security & Technical Debt Dashboard
Reads security_debt_log.json and renders interactive charts + filterable table.
Run with:  streamlit run app.py
"""

import json
import os
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ── Config ────────────────────────────────────────────────────────────────────
DB_FILE = "security_debt_log.json"
SEVERITY_ORDER = ["High", "Medium", "Low"]
SEVERITY_COLORS = {"High": "#e63946", "Medium": "#f4a261", "Low": "#2a9d8f"}

st.set_page_config(
    page_title="SecureDebt Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  .metric-card {
    background: #f7f8fa;
    border-left: 5px solid #ccc;
    border-radius: 8px;
    padding: 18px 24px;
    margin-bottom: 8px;
  }
  .card-high   { border-color: #e63946; }
  .card-medium { border-color: #f4a261; }
  .card-low    { border-color: #2a9d8f; }
  .card-total  { border-color: #3b82d4; }
  .card-title  { font-size: 13px; color: #57606a; margin-bottom: 4px; }
  .card-value  { font-size: 38px; font-weight: 700; color: #1f2328; }
  h1 { color: #1f2328 !important; }
</style>
""", unsafe_allow_html=True)

# ── Data loading ──────────────────────────────────────────────────────────────
@st.cache_data(ttl=30)
def load_data() -> pd.DataFrame:
    if not os.path.exists(DB_FILE):
        return pd.DataFrame()
    with open(DB_FILE, "r", encoding="utf-8-sig") as f:
        records = json.load(f)
    if not records:
        return pd.DataFrame()
    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df["severity"] = pd.Categorical(df["severity"], categories=SEVERITY_ORDER, ordered=True)
    # Derive top-level directory for hotspot grouping
    df["directory"] = df["file_path"].apply(
        lambda p: p.split("/")[0] if "/" in p else "root"
    )
    return df


df_full = load_data()

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🛡️  Security Vulnerability & Technical Debt Dashboard")
if not df_full.empty:
    last_scan = df_full["timestamp"].max()
    st.caption(f"Last scan: **{last_scan.strftime('%Y-%m-%d %H:%M UTC')}**  |  "
               f"Database: `{DB_FILE}`  |  "
               f"Total records: **{len(df_full)}**")
else:
    st.warning("No data found. Run `python scanner.py` first.")
    st.stop()

st.divider()

# ── Sidebar filters ───────────────────────────────────────────────────────────
with st.sidebar:
    st.header("🔍 Filters")
    sel_severity = st.multiselect(
        "Severity", SEVERITY_ORDER, default=SEVERITY_ORDER
    )
    all_cats = sorted(df_full["defect_category"].unique())
    sel_cats = st.multiselect("Defect Category", all_cats, default=all_cats)
    search_text = st.text_input("Search detected text", placeholder="e.g. eval, pickle, password")

    st.divider()
    if st.button("🔄 Refresh Data"):
        st.cache_data.clear()
        st.rerun()

# Apply filters
df = df_full[
    df_full["severity"].isin(sel_severity) &
    df_full["defect_category"].isin(sel_cats)
]
if search_text:
    mask = (
        df["detected_text"].str.contains(search_text, case=False, na=False) |
        df["description"].str.contains(search_text, case=False, na=False) |
        df["file_path"].str.contains(search_text, case=False, na=False)
    )
    df = df[mask]

# ── Metric cards ──────────────────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)

counts = {s: int((df_full["severity"] == s).sum()) for s in SEVERITY_ORDER}
total = sum(counts.values())

with col1:
    st.markdown(f"""
    <div class="metric-card card-total">
      <div class="card-title">TOTAL VULNERABILITIES</div>
      <div class="card-value">{total}</div>
    </div>""", unsafe_allow_html=True)
with col2:
    st.markdown(f"""
    <div class="metric-card card-high">
      <div class="card-title">🔴 HIGH</div>
      <div class="card-value">{counts['High']}</div>
    </div>""", unsafe_allow_html=True)
with col3:
    st.markdown(f"""
    <div class="metric-card card-medium">
      <div class="card-title">🟠 MEDIUM</div>
      <div class="card-value">{counts['Medium']}</div>
    </div>""", unsafe_allow_html=True)
with col4:
    st.markdown(f"""
    <div class="metric-card card-low">
      <div class="card-title">🟢 LOW</div>
      <div class="card-value">{counts['Low']}</div>
    </div>""", unsafe_allow_html=True)

st.divider()

# ── Charts row ────────────────────────────────────────────────────────────────
chart_col1, chart_col2 = st.columns([1, 1])

# Chart 1: Technical Debt Hotspots — treemap by file
with chart_col1:
    st.subheader("📁 Technical Debt Hotspots (Treemap)")
    hotspot_df = (
        df_full.groupby(["directory", "file_path", "severity"])
        .size()
        .reset_index(name="count")
    )
    if not hotspot_df.empty:
        fig_tree = px.treemap(
            hotspot_df,
            path=["directory", "file_path", "severity"],
            values="count",
            color="severity",
            color_discrete_map=SEVERITY_COLORS,
            hover_data={"count": True},
        )
        fig_tree.update_layout(
            margin=dict(l=0, r=0, t=30, b=0),
            height=380,
        )
        fig_tree.update_traces(textinfo="label+value")
        st.plotly_chart(fig_tree, use_container_width=True)
    else:
        st.info("No data for treemap with current filters.")

# Chart 2: Defect category breakdown — horizontal bar
with chart_col2:
    st.subheader("📊 Defect Category Breakdown")
    cat_df = (
        df_full.groupby(["defect_category", "severity"])
        .size()
        .reset_index(name="count")
    )
    if not cat_df.empty:
        fig_bar = px.bar(
            cat_df.sort_values("count", ascending=True),
            x="count",
            y="defect_category",
            color="severity",
            orientation="h",
            color_discrete_map=SEVERITY_COLORS,
            category_orders={"severity": SEVERITY_ORDER},
            text="count",
        )
        fig_bar.update_layout(
            yaxis_title="",
            xaxis_title="Number of findings",
            legend_title="Severity",
            height=380,
            margin=dict(l=0, r=0, t=30, b=0),
        )
        fig_bar.update_traces(textposition="outside")
        st.plotly_chart(fig_bar, use_container_width=True)
    else:
        st.info("No data for bar chart with current filters.")

st.divider()

# Chart 3: Severity over time (if multiple scans exist)
if df_full["timestamp"].nunique() > 1:
    st.subheader("📈 Vulnerability Trend Over Time")
    trend_df = (
        df_full.groupby([df_full["timestamp"].dt.date, "severity"])
        .size()
        .reset_index(name="count")
    )
    trend_df.columns = ["date", "severity", "count"]
    fig_trend = px.line(
        trend_df, x="date", y="count", color="severity",
        color_discrete_map=SEVERITY_COLORS,
        markers=True,
    )
    fig_trend.update_layout(height=300, margin=dict(l=0, r=0, t=10, b=0))
    st.plotly_chart(fig_trend, use_container_width=True)
    st.divider()

# ── Searchable / filterable data table ───────────────────────────────────────
st.subheader(f"🔎 Active Vulnerabilities ({len(df)} shown)")

display_cols = ["severity", "defect_category", "file_path", "line_number", "description", "detected_text", "timestamp"]
display_df = df[display_cols].copy()
display_df["timestamp"] = display_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M UTC")
display_df = display_df.sort_values(["severity", "file_path"])

# Colour-code severity column
def color_severity(val):
    colors = {"High": "background-color:#fce4e4;color:#c0392b;font-weight:bold",
              "Medium": "background-color:#fef3e2;color:#d35400;font-weight:bold",
              "Low": "background-color:#e8f8f5;color:#1a7a6a;font-weight:bold"}
    return colors.get(val, "")

styled = display_df.style.applymap(color_severity, subset=["severity"])
st.dataframe(styled, use_container_width=True, height=450)

# ── Download button ───────────────────────────────────────────────────────────
csv_data = display_df.to_csv(index=False)
st.download_button(
    label="⬇️  Export filtered results as CSV",
    data=csv_data,
    file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
    mime="text/csv",
)

st.divider()
st.caption("SecureDebt Dashboard — powered by Streamlit + Plotly  |  Run `python scanner.py` to refresh findings.")
