import streamlit as st
import sqlite3
import pandas as pd
import os

# Configuration
st.set_page_config(
    page_title="NIDS Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# Connect to database
db_path = os.path.join(os.path.dirname(__file__), 'logs', 'alerts.db')

def get_connection():
    if not os.path.exists(os.path.dirname(db_path)):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
    return sqlite3.connect(db_path, check_same_thread=False)

def init_db_if_not_exists():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS TRAFFIC_LOG (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            destination_ip TEXT,
            port INTEGER,
            protocol TEXT,
            classification TEXT,
            timestamp TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ALERT (
            alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER,
            severity_level TEXT,
            resolution_status TEXT,
            generated_at TEXT,
            FOREIGN KEY(log_id) REFERENCES TRAFFIC_LOG(log_id)
        )
    ''')
    conn.commit()
    conn.close()

# Initialize if missing
init_db_if_not_exists()

# Title
st.title("🛡️ NIDS Streamlit Command Center")
st.markdown("Real-time threat monitoring and historical forensics dashboard.")

# Auto refresh logic
st.sidebar.title("Controls")
if st.sidebar.button("Refresh Data"):
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.info("This dashboard automatically reflects changes made to the `alerts.db` SQLite tracking database.")

# Data fetching
try:
    conn = get_connection()
    
    # Traffic query
    df_traffic = pd.read_sql_query("SELECT * FROM TRAFFIC_LOG ORDER BY timestamp DESC LIMIT 1000", conn)
    
    # Alerts query
    df_alerts = pd.read_sql_query('''
        SELECT a.alert_id, a.severity_level, a.resolution_status, a.generated_at,
               t.source_ip, t.destination_ip, t.port, t.classification
        FROM ALERT a
        JOIN TRAFFIC_LOG t ON a.log_id = t.log_id
        ORDER BY a.generated_at DESC
        LIMIT 500
    ''', conn)
    
    conn.close()
except Exception as e:
    st.error(f"Error reading database: {e}")
    df_traffic = pd.DataFrame()
    df_alerts = pd.DataFrame()

# Metrics
col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Total Flows Logged", len(df_traffic) if not df_traffic.empty else 0)
with col2:
    st.metric("Total Intrusions Detected", len(df_alerts) if not df_alerts.empty else 0)
with col3:
    high_severity = len(df_alerts[df_alerts['severity_level'] == 'High']) if not df_alerts.empty and 'severity_level' in df_alerts.columns else 0
    st.metric("High Severity Alerts", high_severity)

st.markdown("---")

# Historical Forensics Chart
st.subheader("Historical Forensics: Traffic Over Time")
if not df_traffic.empty:
    df_traffic['timestamp'] = pd.to_datetime(df_traffic['timestamp'])
    
    # Group by minute and classification
    time_grouped = df_traffic.groupby([pd.Grouper(key='timestamp', freq='1Min'), 'classification']).size().unstack(fill_value=0)
    
    st.line_chart(time_grouped)
else:
    st.info("No traffic logged yet. Ensure the packet sniffer is running.")

st.markdown("---")

# Recent Alerts Table
st.subheader("Latest Intrusion Alerts")
if not df_alerts.empty:
    def color_severity(val):
        color = '#ffcccc' if val == 'High' else ('#ffe6cc' if val == 'Medium' else '')
        return f'background-color: {color}' if color else ''

    styled_df = df_alerts.style.applymap(color_severity, subset=['severity_level'])
    st.dataframe(styled_df, use_container_width=True)
else:
    st.info("No alerts logged yet. System is clear.")
