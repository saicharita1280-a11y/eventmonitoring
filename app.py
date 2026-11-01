
import streamlit as st
import pandas as pd
import plotly.express as px
import xml.etree.ElementTree as ET
import tempfile
import os
from Evtx.Evtx import Evtx
from datetime import datetime

# ==========================================
# 1. PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="SecureWatch | Event Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==========================================
# 2. CUSTOM CSS
# ==========================================

st.markdown("""
<style>

.stApp {
    background-color: #0B1120;
    color: #F1F5F9;
}

[data-testid="stSidebar"] {
    background-color: #111827;
    border-right: 1px solid #263449;
}

h1, h2, h3 {
    color: #F8FAFC !important;
}

p, label {
    color: #CBD5E1;
}

.metric-card {
    background: linear-gradient(135deg, #17243A, #1E293B);
    border: 1px solid #334155;
    padding: 20px;
    border-radius: 14px;
    min-height: 115px;
}

.metric-label {
    color: #94A3B8;
    font-size: 14px;
}

.metric-value {
    color: #F8FAFC;
    font-size: 30px;
    font-weight: bold;
    margin-top: 8px;
}

.section-card {
    background: #111C2E;
    border: 1px solid #263449;
    padding: 18px;
    border-radius: 12px;
}

div.stButton > button {
    background-color: #2563EB;
    color: white;
    border-radius: 8px;
    border: none;
    padding: 8px 18px;
}

div.stButton > button:hover {
    background-color: #1D4ED8;
    color: white;
}

</style>
""", unsafe_allow_html=True)


# ==========================================
# 3. DEMO DATA
# ==========================================

def demo_data():

    records = [
        [4624, "Information", "Security", "Security", "Successful login"],
        [4625, "Warning", "Security", "Security", "Failed login attempt"],
        [4625, "Warning", "Security", "Security", "Failed login attempt"],
        [4625, "Warning", "Security", "Security", "Failed login attempt"],
        [1001, "Error", "Application Error", "Application", "Application crash"],
        [6005, "Information", "EventLog", "System", "Event log service started"],
        [6006, "Information", "EventLog", "System", "Event log service stopped"],
        [7045, "Warning", "Service Control Manager", "System", "New service installed"],
        [4720, "Warning", "Security", "Security", "New user account created"],
        [4624, "Information", "Security", "Security", "Successful login"],
        [1102, "Warning", "Security", "Security", "Audit log cleared"],
        [1000, "Error", "Application Error", "Application", "Application failure"],
        [4625, "Warning", "Security", "Security", "Failed login attempt"],
        [4624, "Information", "Security", "Security", "Successful login"],
        [41, "Critical", "Kernel-Power", "System", "Unexpected system shutdown"],
    ]

    df = pd.DataFrame(
        records,
        columns=[
            "Event ID", "Level", "Source",
            "Log", "Message"
        ]
    )

    df["Date and Time"] = pd.date_range(
        end=pd.Timestamp.now(),
        periods=len(df),
        freq="10min"
    )

    df["Computer"] = "DEMO-WINDOWS-PC"
    df["Event Record ID"] = range(1001, 1001 + len(df))

    return df


# ==========================================
# 4. NORMALIZE CSV DATA
# ==========================================

def normalize_csv(df):

    df.columns = [str(c).strip() for c in df.columns]

    aliases = {
        "Event ID": ["Event ID", "EventId", "Id"],
        "Level": ["Level", "LevelDisplayName"],
        "Source": ["Source", "Provider", "ProviderName"],
        "Log": ["Log", "LogName", "Channel"],
        "Message": ["Message", "Description"],
        "Date and Time": [
            "Date and Time", "TimeCreated",
            "TimeCreated SystemTime", "Date"
        ],
        "Computer": ["Computer", "MachineName"],
        "Event Record ID": ["Event Record ID", "RecordId"]
    }

    lower_columns = {c.lower(): c for c in df.columns}

    result = pd.DataFrame()

    for target, possible_names in aliases.items():

        found = None

        for name in possible_names:
            if name.lower() in lower_columns:
                found = lower_columns[name.lower()]
                break

        if found is not None:
            result[target] = df[found]
        else:
            result[target] = ""

    result["Event ID"] = result["Event ID"].astype(str)
    result["Date and Time"] = pd.to_datetime(
        result["Date and Time"],
        errors="coerce",
        utc=True
    ).dt.tz_convert(None)

    result["Level"] = result["Level"].astype(str).str.strip()

    level_map = {
        "1": "Critical",
        "2": "Error",
        "3": "Warning",
        "4": "Information",
        "5": "Verbose",
        "0": "Unknown"
    }

    result["Level"] = result["Level"].apply(
        lambda x: level_map.get(x, x.title())
    )

    return result.dropna(subset=["Date and Time"])


# ==========================================
# 5. READ EVTX FILES
# ==========================================

def read_evtx(uploaded_file):

    records = []

    with tempfile.NamedTemporaryFile(
        suffix=".evtx", delete=False
    ) as temp:

        temp.write(uploaded_file.getvalue())
        temp_path = temp.name

    try:

        with Evtx(temp_path) as log:

            for record in log.records():

                try:
                    root = ET.fromstring(record.xml())

                    def find_text(tag):
                        for element in root.iter():
                            if element.tag.split("}")[-1] == tag:
                                return element.text or ""
                        return ""

                    event_id = find_text("EventID")
                    provider = ""

                    for element in root.iter():
                        if element.tag.split("}")[-1] == "Provider":
                            provider = element.attrib.get("Name", "")
                            break

                    system_fields = {}

                    for element in root.iter():
                        tag = element.tag.split("}")[-1]

                        if tag == "TimeCreated":
                            system_fields["time"] = element.attrib.get(
                                "SystemTime", ""
                            )

                        if tag == "Channel":
                            system_fields["channel"] = element.text or ""

                        if tag == "Computer":
                            system_fields["computer"] = element.text or ""

                        if tag == "Level":
                            system_fields["level"] = element.text or ""

                        if tag == "EventRecordID":
                            system_fields["record_id"] = element.text or ""

                    level_map = {
                        "1": "Critical",
                        "2": "Error",
                        "3": "Warning",
                        "4": "Information",
                        "5": "Verbose"
                    }

                    message_parts = []

                    for element in root.iter():
                        if element.tag.split("}")[-1] == "Data":
                            if element.text:
                                message_parts.append(element.text)

                    message = " | ".join(message_parts)

                    records.append({
                        "Event ID": event_id,
                        "Level": level_map.get(
                            system_fields.get("level", ""),
                            "Unknown"
                        ),
                        "Source": provider,
                        "Log": system_fields.get("channel", ""),
                        "Message": message or "Raw event data",
                        "Date and Time": system_fields.get("time", ""),
                        "Computer": system_fields.get("computer", ""),
                        "Event Record ID": system_fields.get(
                            "record_id", ""
                        )
                    })

                except Exception:
                    continue

    finally:
        os.remove(temp_path)

    if not records:
        raise ValueError("No readable events found in this EVTX file.")

    return normalize_csv(pd.DataFrame(records))


# ==========================================
# 6. HEADER
# ==========================================

st.markdown("""
# 🛡️ SECUREWATCH
### Windows Event Log Monitoring & Security Analysis
""")

st.caption(
    "Monitor system events | Analyze security activity | Detect suspicious behavior"
)

st.divider()


# ==========================================
# 7. SIDEBAR
# ==========================================

st.sidebar.title("🛡️ SECUREWATCH")

st.sidebar.caption("EVENT MONITORING PLATFORM")

st.sidebar.divider()

st.sidebar.subheader("Data Source")

upload = st.sidebar.file_uploader(
    "Upload Windows Event Logs",
    type=["csv", "evtx"]
)

if "events_df" not in st.session_state:
    st.session_state.events_df = demo_data()

if st.sidebar.button("Load Demo Data", use_container_width=True):
    st.session_state.events_df = demo_data()
    st.session_state.data_source = "Demonstration data"

if upload is not None:

    try:
        if upload.name.lower().endswith(".evtx"):
            st.session_state.events_df = read_evtx(upload)
        else:
            uploaded_df = pd.read_csv(upload)
            st.session_state.events_df = normalize_csv(uploaded_df)

        st.session_state.data_source = upload.name

    except Exception as e:
        st.sidebar.error(f"Could not read file: {e}")

df = st.session_state.events_df.copy()

st.sidebar.divider()

st.sidebar.subheader("Monitoring Filters")

levels = sorted(df["Level"].dropna().unique().tolist())

selected_levels = st.sidebar.multiselect(
    "Event Level",
    levels,
    default=levels
)

event_ids = st.sidebar.text_input(
    "Search Event ID",
    placeholder="Example: 4625"
)

search_text = st.sidebar.text_input(
    "Search Message or Source"
)


# ==========================================
# 8. FILTER DATA
# ==========================================

filtered = df.copy()

if selected_levels:
    filtered = filtered[filtered["Level"].isin(selected_levels)]
else:
    filtered = filtered.iloc[0:0]

if event_ids.strip():
    filtered = filtered[
        filtered["Event ID"].astype(str).str.contains(
            event_ids.strip(), case=False, na=False
        )
    ]

if search_text.strip():

    search = search_text.strip()

    filtered = filtered[
        filtered["Message"].astype(str).str.contains(
            search, case=False, na=False
        )
        |
        filtered["Source"].astype(str).str.contains(
            search, case=False, na=False
        )
    ]


# ==========================================
# 9. METRIC DASHBOARD
# ==========================================

total = len(filtered)

critical = (filtered["Level"] == "Critical").sum()
errors = (filtered["Level"] == "Error").sum()
warnings = (filtered["Level"] == "Warning").sum()
information = (filtered["Level"] == "Information").sum()

st.subheader("📊 Monitoring Overview")

st.caption(
    f"Data source: {st.session_state.get('data_source', 'Demonstration data')}"
)

c1, c2, c3, c4, c5 = st.columns(5)

metrics = [
    (c1, "TOTAL EVENTS", total, "#38BDF8"),
    (c2, "CRITICAL", critical, "#F43F5E"),
    (c3, "ERRORS", errors, "#FB7185"),
    (c4, "WARNINGS", warnings, "#FBBF24"),
    (c5, "INFORMATION", information, "#34D399")
]

for col, label, value, color in metrics:

    with col:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">{label}</div>
                <div class="metric-value" style="color:{color}">
                    {value}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

st.write("")


# ==========================================
# 10. EVENT ANALYTICS
# ==========================================

st.subheader("📈 Event Analytics")

left, right = st.columns(2)

with left:

    st.markdown("#### Event Level Distribution")

    if not filtered.empty:

        level_counts = filtered["Level"].value_counts().reset_index()
        level_counts.columns = ["Level", "Count"]

        fig = px.pie(
            level_counts,
            names="Level",
            values="Count",
            hole=0.55,
            template="plotly_dark"
        )

        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#E2E8F0"
        )

        st.plotly_chart(fig, use_container_width=True)

    else:
        st.info("No events available for this filter.")


with right:

    st.markdown("#### Event Timeline")

    timeline_df = filtered.dropna(
        subset=["Date and Time"]
    ).copy()

    if not timeline_df.empty:

        timeline_df["Hour"] = (
            timeline_df["Date and Time"].dt.floor("h")
        )

        timeline = timeline_df.groupby(
            "Hour"
        ).size().reset_index(name="Events")

        fig = px.line(
            timeline,
            x="Hour",
            y="Events",
            markers=True,
            template="plotly_dark"
        )

        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#E2E8F0"
        )

        st.plotly_chart(fig, use_container_width=True)

    else:
        st.info("No timeline data available.")


# ==========================================
# 11. SECURITY ALERT CENTER
# ==========================================

st.divider()

st.subheader("🚨 Security Alert Center")

alerts = []

failed_logins = (
    filtered["Event ID"].astype(str) == "4625"
).sum()

if failed_logins >= 5:
    alerts.append((
        "HIGH",
        f"{failed_logins} failed login events detected."
    ))

if (filtered["Event ID"].astype(str) == "1102").any():
    alerts.append((
        "HIGH",
        "Windows Security audit log cleared event detected."
    ))

if (filtered["Event ID"].astype(str) == "4720").any():
    alerts.append((
        "MEDIUM",
        "New user account creation event detected."
    ))

if (filtered["Event ID"].astype(str) == "7045").any():
    alerts.append((
        "MEDIUM",
        "New Windows service installation event detected."
    ))

if critical > 0:
    alerts.append((
        "HIGH",
        f"{critical} critical-level events detected."
    ))

if errors > 0:
    alerts.append((
        "MEDIUM",
        f"{errors} error-level events detected."
    ))

if not alerts:
    st.success("No configured security alerts detected in the selected events.")

else:

    for priority, message in alerts:

        if priority == "HIGH":
            st.error(f"🔴 HIGH PRIORITY: {message}")

        else:
            st.warning(f"🟠 MEDIUM PRIORITY: {message}")


# ==========================================
# 12. EVENT LOG TABLE
# ==========================================

st.divider()

st.subheader("📋 Event Log Explorer")

st.caption("Explore and inspect the available Windows event records.")

display_columns = [
    "Date and Time",
    "Event ID",
    "Level",
    "Source",
    "Log",
    "Computer",
    "Message"
]

st.dataframe(
    filtered[display_columns].sort_values(
        "Date and Time",
        ascending=False
    ),
    use_container_width=True,
    hide_index=True
)

# ==========================================
# 13. EVENT DETAILS
# ==========================================

st.divider()

st.subheader("🔍 Event Details")

if not filtered.empty:

    selected_index = st.selectbox(
        "Select an event",
        filtered.index,
        format_func=lambda i: (
            f"Event {filtered.loc[i, 'Event ID']} | "
            f"{filtered.loc[i, 'Level']} | "
            f"{filtered.loc[i, 'Source']}"
        )
    )

    selected_event = filtered.loc[selected_index]

    d1, d2 = st.columns(2)

    with d1:
        st.write("**Event ID:**", selected_event["Event ID"])
        st.write("**Level:**", selected_event["Level"])
        st.write("**Source:**", selected_event["Source"])
        st.write("**Log:**", selected_event["Log"])

    with d2:
        st.write("**Computer:**", selected_event["Computer"])
        st.write("**Date and Time:**", selected_event["Date and Time"])
        st.write("**Record ID:**", selected_event["Event Record ID"])

    st.markdown("**Event Message**")

    st.info(str(selected_event["Message"]))

else:
    st.info("No event details available.")


# ==========================================
# 14. EXPORT REPORT
# ==========================================

st.divider()

st.subheader("📥 Export Monitoring Report")

csv_data = filtered.to_csv(index=False).encode("utf-8-sig")

st.download_button(
    label="⬇️ Download Event Report (CSV)",
    data=csv_data,
    file_name="Windows_Event_Monitor_Report.csv",
    mime="text/csv",
    use_container_width=True
)


# ==========================================
# 15. FOOTER
# ==========================================

st.divider()

st.markdown(
    """
    <div style="text-align:center;color:#64748B;padding:15px;">
        🛡️ SECUREWATCH | Windows Event Log Monitoring System<br>
        Built using Python, Streamlit, Pandas and Plotly
    </div>
    """,
    unsafe_allow_html=True
)
