"""
LLM Firewall Dashboard - Streamlit Application

FIXED VERSION - Resolved ambiguous timestamp column error
"""

import streamlit as st
import sqlite3
import pandas as pd
import json
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go

# Page config
st.set_page_config(
    page_title="LLM Firewall Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .reportview-container .main .block-container {
        padding-top: 2rem;
    }
    div[data-testid="stMetric"] {
        background-color:#2A2E35;   
        border-radius: 10px;
        padding: 12px;
    }
</style>
""", unsafe_allow_html=True)

# Database connection
@st.cache_resource
def get_db_connection():
    conn = sqlite3.connect('llm_firewall.db', check_same_thread=False)
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create tables if they don't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            user_id TEXT,
            prompt_length INTEGER,
            response_length INTEGER,
            latency_ms REAL,
            status TEXT,
            threat_type TEXT,
            blocked BOOLEAN,
            llm_provider TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            request_id INTEGER,
            threat_type TEXT,
            severity TEXT,
            prompt_snippet TEXT,
            response_snippet TEXT,
            action_taken TEXT,
            details TEXT,
            FOREIGN KEY (request_id) REFERENCES requests (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            type TEXT,
            config TEXT,
            enabled BOOLEAN DEFAULT 1,
            last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert default policies if none exist
    cursor.execute('SELECT COUNT(*) FROM policies')
    if cursor.fetchone()[0] == 0:
        default_policies = [
            ('prompt_injection', 'input', json.dumps({
                'patterns': ['ignore previous instructions', 'system:', 'you are now', 'disregard'],
                'threshold': 0.7
            }), 1),
            ('pii_detection', 'output', json.dumps({
                'patterns': ['SSN', 'credit card', 'API key', 'password'],
                'redact': True
            }), 1),
            ('data_exfiltration', 'output', json.dumps({
                'max_tokens': 2000,
                'check_secrets': True
            }), 1)
        ]
        cursor.executemany(
            'INSERT INTO policies (name, type, config, enabled) VALUES (?, ?, ?, ?)',
            default_policies
        )
    
    conn.commit()
    return conn

# Initialize database
conn = init_db()

# Sidebar navigation
st.sidebar.title("🛡️ LLM Firewall")
st.sidebar.markdown("---")
page = st.sidebar.radio(
    "Navigation",
    ["📊 Overview", "🚨 Incidents", "⚙️ Policies", "📡 Live Monitor"],
    label_visibility="collapsed"
)

# Helper function to insert sample data
def insert_sample_data():
    cursor = conn.cursor()
    
    try:
        # Clear existing data
        cursor.execute('DELETE FROM requests')
        cursor.execute('DELETE FROM incidents')
        
        # Sample requests with varied data
        threat_types = ['prompt_injection', 'jailbreak', 'data_exfiltration', None]
        users = ['user_1', 'user_2', 'user_3', 'user_4', 'user_5']
        providers = ['openai', 'anthropic', 'cohere']
        
        sample_requests = []
        for i in range(100):
            timestamp = datetime.now() - timedelta(hours=i * 0.5)
            user_id = users[i % len(users)]
            prompt_length = 100 + (i * 17) % 500
            response_length = 300 + (i * 23) % 800
            latency_ms = 80 + (i * 11) % 200
            is_blocked = i % 8 == 0
            status = 'blocked' if is_blocked else 'success'
            threat_type = threat_types[i % len(threat_types)] if is_blocked else None
            llm_provider = providers[i % len(providers)]
            
            sample_requests.append((
                timestamp, user_id, prompt_length, response_length,
                latency_ms, status, threat_type, is_blocked, llm_provider
            ))
        
        cursor.executemany('''
            INSERT INTO requests (timestamp, user_id, prompt_length, response_length, 
                                latency_ms, status, threat_type, blocked, llm_provider)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', sample_requests)
        
        # Sample incidents
        cursor.execute('SELECT id, timestamp FROM requests WHERE blocked = 1')
        blocked_requests = cursor.fetchall()
        
        severities = ['critical', 'high', 'medium', 'low']
        threat_types_incidents = ['prompt_injection', 'jailbreak', 'data_exfiltration', 'pii_leak']
        
        sample_incidents = []
        for i, (req_id, req_timestamp) in enumerate(blocked_requests):
            threat_type = threat_types_incidents[i % len(threat_types_incidents)]
            severity = severities[i % len(severities)]
            prompt_snippet = f'Suspicious prompt #{i}: Ignore all previous instructions and...'
            response_snippet = None
            action_taken = 'blocked'
            details = json.dumps({
                'confidence': 0.85 + (i % 15) / 100,
                'pattern_matched': 'ignore previous',
                'rule_id': f'RULE_{i % 5}'
            })
            
            sample_incidents.append((
                req_timestamp, req_id, threat_type, severity,
                prompt_snippet, response_snippet, action_taken, details
            ))
        
        cursor.executemany('''
            INSERT INTO incidents (timestamp, request_id, threat_type, severity,
                                 prompt_snippet, response_snippet, action_taken, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', sample_incidents)
        
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        st.error(f"Error generating data: {str(e)}")
        return False

# Sidebar - Sample data and info
st.sidebar.markdown("---")
if st.sidebar.button("🔄 Generate Sample Data", use_container_width=True):
    with st.spinner("Generating sample data..."):
        if insert_sample_data():
            st.sidebar.success("✅ Sample data generated!")
            st.rerun()

st.sidebar.markdown("---")
st.sidebar.caption("**LLM Firewall** v1.0")
st.sidebar.caption("Protecting AI applications")
st.sidebar.caption(f"Updated: {datetime.now().strftime('%H:%M:%S')}")

# Overview Page
if page == "📊 Overview":
    st.title("📊 Security Overview Dashboard")
    
    # Time filter
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        time_range = st.selectbox(
            "Time Range",
            ["Last Hour", "Last 24 Hours", "Last 7 Days", "Last 30 Days"]
        )
    with col2:
        auto_refresh = st.checkbox("Auto-refresh", value=False)
    with col3:
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()
    
    if auto_refresh:
        st.markdown('<meta http-equiv="refresh" content="30">', unsafe_allow_html=True)
    
    time_mapping = {
        "Last Hour": 1,
        "Last 24 Hours": 24,
        "Last 7 Days": 24 * 7,
        "Last 30 Days": 24 * 30
    }
    hours = time_mapping[time_range]
    
    # Fetch metrics
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT COUNT(*) FROM requests 
        WHERE timestamp > datetime('now', '-' || ? || ' hours')
    ''', (hours,))
    total_requests = cursor.fetchone()[0]
    
    cursor.execute('''
        SELECT COUNT(*) FROM requests 
        WHERE blocked = 1 AND timestamp > datetime('now', '-' || ? || ' hours')
    ''', (hours,))
    blocked_requests = cursor.fetchone()[0]
    
    cursor.execute('''
        SELECT AVG(latency_ms) FROM requests 
        WHERE timestamp > datetime('now', '-' || ? || ' hours')
    ''', (hours,))
    avg_latency = cursor.fetchone()[0] or 0
    
    cursor.execute('''
        SELECT COUNT(DISTINCT threat_type) FROM requests 
        WHERE blocked = 1 AND threat_type IS NOT NULL 
        AND timestamp > datetime('now', '-' || ? || ' hours')
    ''', (hours,))
    unique_threats = cursor.fetchone()[0]
    
    # Display metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Total Requests",
            f"{total_requests:,}",
            delta=None,
            help="Total number of requests processed"
        )
    
    with col2:
        block_rate = (blocked_requests / total_requests * 100) if total_requests > 0 else 0
        st.metric(
            "Blocked Requests",
            f"{blocked_requests:,}",
            delta=f"{block_rate:.1f}%",
            delta_color="inverse",
            help="Requests blocked by security filters"
        )
    
    with col3:
        st.metric(
            "Avg Latency",
            f"{avg_latency:.0f} ms",
            help="Average response latency"
        )
    
    with col4:
        st.metric(
            "Unique Threats",
            unique_threats,
            help="Number of different threat types detected"
        )
    
    st.markdown("---")
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📈 Requests Over Time")
        cursor.execute('''
            SELECT 
                datetime(timestamp, 'start of hour') as hour,
                SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN blocked = 0 THEN 1 ELSE 0 END) as allowed
            FROM requests
            WHERE timestamp > datetime('now', '-' || ? || ' hours')
            GROUP BY hour
            ORDER BY hour
        ''', (hours,))
        
        df_time = pd.DataFrame(cursor.fetchall(), columns=['hour', 'blocked', 'allowed'])
        
        if not df_time.empty:
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=df_time['hour'],
                y=df_time['allowed'],
                name='Allowed',
                fill='tozeroy',
                line=dict(color='#10b981', width=2),
                mode='lines+markers'
            ))
            fig.add_trace(go.Scatter(
                x=df_time['hour'],
                y=df_time['blocked'],
                name='Blocked',
                fill='tozeroy',
                line=dict(color='#ef4444', width=2),
                mode='lines+markers'
            ))
            fig.update_layout(
                height=300,
                margin=dict(l=0, r=0, t=10, b=0),
                hovermode='x unified',
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
                xaxis_title="Time",
                yaxis_title="Requests"
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("📭 No data available for this time range")
    
    with col2:
        st.subheader("🎯 Threat Distribution")
        cursor.execute('''
            SELECT threat_type, COUNT(*) as count
            FROM requests
            WHERE blocked = 1 AND threat_type IS NOT NULL
            AND timestamp > datetime('now', '-' || ? || ' hours')
            GROUP BY threat_type
        ''', (hours,))
        
        df_threats = pd.DataFrame(cursor.fetchall(), columns=['threat_type', 'count'])
        
        if not df_threats.empty:
            fig = px.pie(
                df_threats,
                values='count',
                names='threat_type',
                color_discrete_sequence=px.colors.qualitative.Bold,
                hole=0.3
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            fig.update_layout(
                height=300,
                margin=dict(l=0, r=0, t=10, b=0),
                showlegend=True
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("📭 No threats detected in this time range")
    
    # Additional charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("⚡ Latency Trend")
        cursor.execute('''
            SELECT 
                datetime(timestamp, 'start of hour') as hour,
                AVG(latency_ms) as avg_latency,
                MIN(latency_ms) as min_latency,
                MAX(latency_ms) as max_latency
            FROM requests
            WHERE timestamp > datetime('now', '-' || ? || ' hours')
            GROUP BY hour
            ORDER BY hour
        ''', (hours,))
        
        df_latency = pd.DataFrame(
            cursor.fetchall(),
            columns=['hour', 'avg_latency', 'min_latency', 'max_latency']
        )
        
        if not df_latency.empty:
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=df_latency['hour'],
                y=df_latency['avg_latency'],
                name='Average',
                line=dict(color='#3b82f6', width=2),
                mode='lines'
            ))
            fig.update_layout(
                height=250,
                margin=dict(l=0, r=0, t=10, b=0),
                xaxis_title="Time",
                yaxis_title="Latency (ms)"
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("📭 No latency data available")
    
    with col2:
        st.subheader("👥 Top Users")
        cursor.execute('''
            SELECT 
                user_id,
                COUNT(*) as total,
                SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked,
                ROUND(AVG(latency_ms), 1) as avg_latency
            FROM requests
            WHERE timestamp > datetime('now', '-' || ? || ' hours')
            GROUP BY user_id
            ORDER BY total DESC
            LIMIT 5
        ''', (hours,))
        
        df_users = pd.DataFrame(
            cursor.fetchall(),
            columns=['User', 'Total', 'Blocked', 'Avg Latency']
        )
        
        if not df_users.empty:
            st.dataframe(df_users, use_container_width=True, hide_index=True)
        else:
            st.info("📭 No user data available")

# Incidents Page
elif page == "🚨 Incidents":
    st.title("🚨 Security Incidents")
    
    # Filters
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        severity_filter = st.multiselect(
            "Severity",
            ["critical", "high", "medium", "low"],
            default=["critical", "high"]
        )
    
    with col2:
        threat_filter = st.multiselect(
            "Threat Type",
            ["prompt_injection", "pii_leak", "data_exfiltration", "jailbreak"],
            default=["prompt_injection", "pii_leak", "data_exfiltration", "jailbreak"]
        )
    
    with col3:
        time_filter = st.selectbox(
            "Time Range",
            ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"]
        )
    
    with col4:
        search_term = st.text_input("🔍 Search", placeholder="Search incidents...")
    
    # Build query - FIXED: Use i.timestamp to avoid ambiguity
    time_clause_map = {
        "Last 24 Hours": "i.timestamp > datetime('now', '-24 hours')",
        "Last 7 Days": "i.timestamp > datetime('now', '-7 days')",
        "Last 30 Days": "i.timestamp > datetime('now', '-30 days')",
        "All Time": "1=1"
    }
    time_clause = time_clause_map[time_filter]
    
    if severity_filter and threat_filter:
        severity_placeholders = ','.join(['?' for _ in severity_filter])
        threat_placeholders = ','.join(['?' for _ in threat_filter])
        
        # FIXED: Explicitly use i.timestamp instead of ambiguous 'timestamp'
        query = f'''
            SELECT 
                i.id,
                i.timestamp,
                i.threat_type,
                i.severity,
                i.prompt_snippet,
                i.action_taken,
                r.user_id
            FROM incidents i
            LEFT JOIN requests r ON i.request_id = r.id
            WHERE {time_clause}
            AND i.severity IN ({severity_placeholders})
            AND i.threat_type IN ({threat_placeholders})
            ORDER BY i.timestamp DESC
        '''
        
        cursor = conn.cursor()
        cursor.execute(query, severity_filter + threat_filter)
        incidents_data = cursor.fetchall()
    else:
        incidents_data = []
    
    if incidents_data:
        df_incidents = pd.DataFrame(
            incidents_data,
            columns=['ID', 'Timestamp', 'Threat Type', 'Severity',
                    'Prompt Snippet', 'Action', 'User ID']
        )
        
        # Apply search filter
        if search_term:
            mask = df_incidents.apply(
                lambda row: search_term.lower() in str(row).lower(),
                axis=1
            )
            df_incidents = df_incidents[mask]
        
        # Pagination
        page_size = st.selectbox("Items per page", [10, 25, 50, 100], index=1)
        total_pages = (len(df_incidents) - 1) // page_size + 1 if len(df_incidents) > 0 else 1
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            page_num = st.number_input(
                f"Page (1-{total_pages})",
                min_value=1,
                max_value=total_pages,
                value=1
            )
        
        start_idx = (page_num - 1) * page_size
        end_idx = start_idx + page_size
        df_page = df_incidents.iloc[start_idx:end_idx]
        
        # Style function
        def highlight_severity(row):
            if row['Severity'] in ['critical', 'high']:
                return ['background-color: #fca5a5; color: #7f1d1d; font-weight: bold'] * len(row)
            return [''] * len(row)
        
        styled_df = df_page.style.apply(highlight_severity, axis=1)
        st.dataframe(styled_df, use_container_width=True, hide_index=True)
        
        # Stats
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Incidents", len(df_incidents))
        with col2:
            critical_high = len(df_incidents[df_incidents['Severity'].isin(['critical', 'high'])])
            st.metric("Critical/High", critical_high)
        with col3:
            unique_users = df_incidents['User ID'].nunique()
            st.metric("Affected Users", unique_users)
        
        # Export
        st.markdown("---")
        csv = df_incidents.to_csv(index=False)
        st.download_button(
            label="📥 Export to CSV",
            data=csv,
            file_name=f"incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )
        
        # Incident details
        with st.expander("🔍 View Incident Details"):
            selected_id = st.selectbox("Select Incident ID", df_incidents['ID'].tolist())
            
            if selected_id:
                cursor.execute('''
                    SELECT i.*, r.prompt_length, r.response_length, r.latency_ms
                    FROM incidents i
                    LEFT JOIN requests r ON i.request_id = r.id
                    WHERE i.id = ?
                ''', (selected_id,))
                
                incident = cursor.fetchone()
                
                if incident:
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("**📅 Timestamp:**")
                        st.text(incident[1])
                        st.markdown("**⚠️ Threat Type:**")
                        st.text(incident[3])
                        st.markdown("**🎯 Severity:**")
                        st.text(incident[4])
                    
                    with col2:
                        st.markdown("**🔢 Request ID:**")
                        st.text(incident[2])
                        st.markdown("**⚡ Latency:**")
                        st.text(f"{incident[11]} ms" if len(incident) > 11 and incident[11] else "N/A")
                        st.markdown("**🛡️ Action:**")
                        st.text(incident[7])
                    
                    st.markdown("**📝 Prompt Snippet:**")
                    st.code(incident[5] or "N/A", language=None)
                    
                    if incident[8]:
                        st.markdown("**📊 Additional Details:**")
                        try:
                            details = json.loads(incident[8])
                            st.json(details)
                        except:
                            st.text(incident[8])
    else:
        st.info("📭 No incidents found matching the selected filters.")

# Policies Page
elif page == "⚙️ Policies":
    st.title("⚙️ Security Policies")
    
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, type, config, enabled, last_updated FROM policies')
    policies = cursor.fetchall()
    
    if not policies:
        st.info("📭 No policies configured. Add a new policy below.")
    
    # Display policies
    for policy in policies:
        policy_id, name, policy_type, config, enabled, last_updated = policy
        
        status_icon = "🟢" if enabled else "🔴"
        with st.expander(f"{status_icon} {name.replace('_', ' ').title()}", expanded=False):
            col1, col2 = st.columns([3, 1])
            
            with col1:
                st.markdown(f"**Type:** `{policy_type}`")
                st.markdown(f"**Last Updated:** {last_updated}")
                
                try:
                    config_json = json.loads(config)
                    config_str = json.dumps(config_json, indent=2)
                except:
                    config_str = config
                
                new_config = st.text_area(
                    "Configuration (JSON)",
                    value=config_str,
                    height=150,
                    key=f"config_{policy_id}"
                )
                
                if st.button("💾 Save Configuration", key=f"save_{policy_id}"):
                    try:
                        json.loads(new_config)
                        cursor.execute('''
                            UPDATE policies 
                            SET config = ?, last_updated = CURRENT_TIMESTAMP
                            WHERE id = ?
                        ''', (new_config, policy_id))
                        conn.commit()
                        st.success("✅ Configuration updated!")
                        st.rerun()
                    except json.JSONDecodeError:
                        st.error("❌ Invalid JSON format!")
                    except Exception as e:
                        st.error(f"❌ Error: {str(e)}")
            
            with col2:
                new_enabled = st.toggle(
                    "Enabled",
                    value=bool(enabled),
                    key=f"enable_{policy_id}"
                )
                
                if new_enabled != enabled:
                    try:
                        cursor.execute(
                            'UPDATE policies SET enabled = ?, last_updated = CURRENT_TIMESTAMP WHERE id = ?',
                            (new_enabled, policy_id)
                        )
                        conn.commit()
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Error: {str(e)}")
    
    st.markdown("---")
    
    # Add new policy
    with st.expander("➕ Add New Policy"):
        col1, col2 = st.columns(2)
        
        with col1:
            new_name = st.text_input("Policy Name")
            new_type = st.selectbox("Policy Type", ["input", "output"])
        
        with col2:
            new_config_str = st.text_area(
                "Configuration (JSON)",
                value='{\n  "enabled": true\n}',
                height=100
            )
        
        if st.button("➕ Create Policy"):
            if new_name:
                try:
                    json.loads(new_config_str)
                    cursor.execute('''
                        INSERT INTO policies (name, type, config, enabled)
                        VALUES (?, ?, ?, 1)
                    ''', (new_name, new_type, new_config_str))
                    conn.commit()
                    st.success(f"✅ Policy '{new_name}' created!")
                    st.rerun()
                except json.JSONDecodeError:
                    st.error("❌ Invalid JSON format!")
                except sqlite3.IntegrityError:
                    st.error("❌ Policy name already exists!")
                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")
            else:
                st.error("❌ Please enter a policy name!")

# Live Monitor Page
elif page == "📡 Live Monitor":
    st.title("📡 Live Request Monitor")
    
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        st.info("💡 Showing the most recent requests in real-time")
    with col2:
        auto_refresh = st.checkbox("Auto-refresh (5s)", value=False)
    with col3:
        if st.button("🔄 Refresh Now", use_container_width=True):
            st.rerun()
    
    if auto_refresh:
        st.markdown('<meta http-equiv="refresh" content="5">', unsafe_allow_html=True)
    
    # Fetch recent requests
    cursor = conn.cursor()
    cursor.execute('''
        SELECT 
            id,
            timestamp,
            user_id,
            status,
            threat_type,
            latency_ms,
            blocked,
            llm_provider
        FROM requests
        ORDER BY timestamp DESC
        LIMIT 50
    ''')
    
    recent_requests = cursor.fetchall()
    
    if recent_requests:
        df_recent = pd.DataFrame(
            recent_requests,
            columns=['ID', 'Timestamp', 'User', 'Status',
                    'Threat', 'Latency (ms)', 'Blocked', 'Provider']
        )
        
        # Color code function
        def color_status(row):
            if row['Blocked']:
                return ['background-color: #fca5a5; color: #7f1d1d'] * len(row)
            elif row['Status'] == 'success':
                return ['background-color: #86efac; color: #14532d'] * len(row)
            return [''] * len(row)
        
        styled_df = df_recent.style.apply(color_status, axis=1)
        st.dataframe(styled_df, use_container_width=True, hide_index=True)
        
        # Stats
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total", len(df_recent))
        with col2:
            blocked = len(df_recent[df_recent['Blocked'] == 1])
            st.metric("Blocked", blocked)
        with col3:
            avg_latency = df_recent['Latency (ms)'].mean()
            st.metric("Avg Latency", f"{avg_latency:.0f} ms")
        with col4:
            unique_users = df_recent['User'].nunique()
            st.metric("Users", unique_users)
    else:
        st.info("📭 No requests yet. Generate sample data from the sidebar.")