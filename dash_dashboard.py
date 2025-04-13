import dash
from dash import dcc, html, dash_table, Input, Output, State
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
from datetime import datetime
import glob

# Initialize the Dash app with a modern Bootstrap theme
app = dash.Dash(__name__, 
                external_stylesheets=[dbc.themes.FLATLY, 
                                    "https://use.fontawesome.com/releases/v5.15.4/css/all.css"])
app.title = "Cyber Security Dashboard"

# Custom CSS for styling
app.index_string = """
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
        {%css%}
        <style>
            .card {
                border-radius: 10px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                transition: all 0.3s ease;
                margin-bottom: 20px;
            }
            .card:hover {
                transform: translateY(-5px);
                box-shadow: 0 8px 15px rgba(0, 0, 0, 0.2);
            }
            .card-header {
                border-radius: 10px 10px 0 0 !important;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 1px;
                font-size: 0.9rem;
            }
            .metrics-card .card-body {
                padding: 1.5rem;
            }
            .dashboard-title {
                font-weight: 700;
                letter-spacing: -1px;
            }
            .dashboard-subtitle {
                opacity: 0.8;
            }
            .dashboard-footer {
                font-size: 0.8rem;
                opacity: 0.7;
            }
            .nav-tabs .nav-link {
                border-radius: 10px 10px 0 0;
                font-weight: 500;
            }
            .dash-table-container .dash-spreadsheet-container .dash-spreadsheet-inner th {
                font-weight: 600 !important;
                text-transform: uppercase;
                font-size: 0.85rem;
                letter-spacing: 0.5px;
            }
            .stat-highlight {
                font-size: 2.5rem;
                font-weight: 700;
            }
            .stat-label {
                font-size: 0.9rem;
                font-weight: 400;
                opacity: 0.8;
            }
            .refresh-btn {
                border-radius: 20px;
                padding: 0.5rem 1.5rem;
                font-weight: 500;
            }
            .filters-card {
                background: #f8f9fa;
            }
            /* Style priorities with CSS selectors */
            .dash-checklist label:nth-child(1) {
                color: #dc3545;
                font-weight: bold;
            }
            .dash-checklist label:nth-child(2) {
                color: #fd7e14;
                font-weight: bold;
            }
            .dash-checklist label:nth-child(3) {
                color: #17a2b8;
                font-weight: bold;
            }
            .dash-checklist label:nth-child(4) {
                color: #28a745;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
"""

# Get latest files from the output directory
def get_latest_files():
    output_dir = "./output"
    
    # Find the latest file of each type
    login_files = glob.glob(f"{output_dir}/failed_logins_*.csv")
    traffic_files = glob.glob(f"{output_dir}/suspicious_traffic_*.csv")
    alerts_files = glob.glob(f"{output_dir}/enriched_alerts_*.csv")
    
    latest_login = max(login_files, key=os.path.getctime) if login_files else None
    latest_traffic = max(traffic_files, key=os.path.getctime) if traffic_files else None
    latest_alerts = max(alerts_files, key=os.path.getctime) if alerts_files else None
    
    return latest_login, latest_traffic, latest_alerts

# Load initial data
latest_login, latest_traffic, latest_alerts = get_latest_files()

login_df = pd.read_csv(latest_login) if latest_login else pd.DataFrame()
traffic_df = pd.read_csv(latest_traffic) if latest_traffic else pd.DataFrame()
alerts_df = pd.read_csv(latest_alerts) if latest_alerts else pd.DataFrame()

# Convert string timestamps to datetime
if not login_df.empty and 'first_attempt' in login_df.columns:
    login_df['first_attempt'] = pd.to_datetime(login_df['first_attempt'])
    login_df['last_attempt'] = pd.to_datetime(login_df['last_attempt'])

if not traffic_df.empty and 'timestamp' in traffic_df.columns:
    traffic_df['timestamp'] = pd.to_datetime(traffic_df['timestamp'])

if not alerts_df.empty and 'timestamp' in alerts_df.columns:
    alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'])

# App layout
app.layout = dbc.Container([
    # Header with logo and title
    dbc.Row([
        dbc.Col([
            html.Div([
                html.I(className="fas fa-shield-alt fa-3x text-primary me-3 d-inline-block"),
                html.Div([
                    html.H1("Cyber Security Dashboard", className="dashboard-title display-4 m-0 d-inline-block"),
                ], className="d-inline-block align-middle")
            ], className="d-flex align-items-center"),
            html.P("Real-time monitoring and threat analysis for network security", 
                   className="dashboard-subtitle lead mt-2"),
            html.Hr()
        ], width=12)
    ], className="mb-4 mt-3"),
    
    # Filters Row
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-filter me-2"),
                    "Dashboard Filters"
                ], className="d-flex align-items-center"),
                dbc.CardBody([
                    dbc.Row([
                        # Time Range Filter
                        dbc.Col([
                            html.Label("Time Range", className="fw-bold"),
                            dcc.Dropdown(
                                id="time-filter",
                                options=[
                                    {"label": "All Time", "value": "all"},
                                    {"label": "Last 24 Hours", "value": "24h"},
                                    {"label": "Last 7 Days", "value": "7d"},
                                    {"label": "Last 30 Days", "value": "30d"}
                                ],
                                value="all",
                                className="mt-1"
                            )
                        ], lg=4, md=12),
                        
                        # Risk Score Range (for login attempts)
                        dbc.Col([
                            html.Label("Risk Score Range", className="fw-bold"),
                            dcc.RangeSlider(
                                id="risk-range-slider",
                                min=min(login_df['risk_score'].min() if not login_df.empty else 0, 0),
                                max=max(login_df['risk_score'].max() if not login_df.empty else 100, 100),
                                value=[0, 100],
                                marks={0: '0', 25: '25', 50: '50', 75: '75', 100: '100'},
                                step=5,
                                className="mt-3"
                            )
                        ], lg=4, md=12),
                        
                        # Priority Filter (for alerts)
                        dbc.Col([
                            html.Label("Alert Priorities", className="fw-bold"),
                            # Use basic dcc.Checklist without className in options
                            dcc.Checklist(
                                id="priority-checklist",
                                options=[
                                    {"label": " CRITICAL", "value": "CRITICAL"},
                                    {"label": " HIGH", "value": "HIGH"},
                                    {"label": " MEDIUM", "value": "MEDIUM"},
                                    {"label": " LOW", "value": "LOW"}
                                ],
                                value=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                                inline=True,
                                className="mt-2 dash-checklist"
                            )
                        ], lg=4, md=12)
                    ])
                ])
            ], className="mb-4 filters-card")
        ], width=12)
    ]),
    
    # Key Metrics Row
    dbc.Row([
        # Failed Login Attempts
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-user-lock me-2 text-danger"),
                    "Failed Login Attempts"
                ], className="bg-danger text-white d-flex align-items-center"),
                dbc.CardBody([
                    html.Div([
                        html.Div(len(login_df) if not login_df.empty else 0, 
                                className="stat-highlight text-center text-danger"),
                        html.Div(f"High Risk: {len(login_df[login_df['risk_score'] >= 80]) if not login_df.empty else 0}", 
                                className="stat-label text-center")
                    ])
                ])
            ], className="metrics-card")
        ], lg=3, md=6, xs=12),
        
        # Suspicious Traffic Events
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-network-wired me-2 text-warning"),
                    "Suspicious Traffic"
                ], className="bg-warning text-white d-flex align-items-center"),
                dbc.CardBody([
                    html.Div([
                        html.Div(len(traffic_df) if not traffic_df.empty else 0, 
                                className="stat-highlight text-center text-warning"),
                        html.Div(f"High Anomaly: {len(traffic_df[traffic_df['anomaly_score'] >= 80]) if not traffic_df.empty else 0}", 
                                className="stat-label text-center")
                    ])
                ])
            ], className="metrics-card")
        ], lg=3, md=6, xs=12),
        
        # Security Alerts
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-exclamation-triangle me-2 text-info"),
                    "Security Alerts"
                ], className="bg-info text-white d-flex align-items-center"),
                dbc.CardBody([
                    html.Div([
                        html.Div(len(alerts_df) if not alerts_df.empty else 0, 
                                className="stat-highlight text-center text-info"),
                        html.Div(f"Critical: {len(alerts_df[alerts_df['priority'] == 'CRITICAL']) if not alerts_df.empty else 0}", 
                                className="stat-label text-center")
                    ])
                ])
            ], className="metrics-card")
        ], lg=3, md=6, xs=12),
        
        # Actions Required
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-tasks me-2 text-primary"),
                    "Actions Required"
                ], className="bg-primary text-white d-flex align-items-center"),
                dbc.CardBody([
                    html.Div([
                        html.Div(len(alerts_df[alerts_df['action_required'] == True]) if not alerts_df.empty else 0, 
                                className="stat-highlight text-center text-primary"),
                        html.Div("Pending Actions", 
                                className="stat-label text-center")
                    ])
                ])
            ], className="metrics-card")
        ], lg=3, md=6, xs=12)
    ], className="mb-4"),
    
    # Main Charts Row 1
    dbc.Row([
        # Risk Score Distribution
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-chart-bar me-2"),
                    "Login Risk Score Distribution"
                ], className="d-flex align-items-center"),
                dbc.CardBody([
                    dcc.Graph(id="risk-score-graph")
                ])
            ])
        ], lg=6, md=12),
        
        # Anomaly Score Distribution
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-chart-line me-2"),
                    "Traffic Anomaly Score Distribution"
                ], className="d-flex align-items-center"),
                dbc.CardBody([
                    dcc.Graph(id="anomaly-score-graph")
                ])
            ])
        ], lg=6, md=12)
    ], className="mb-4"),
    
    # Main Charts Row 2
    dbc.Row([
        # Alert Priority Distribution
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-chart-pie me-2"),
                    "Alert Priority Distribution"
                ], className="d-flex align-items-center"),
                dbc.CardBody([
                    dcc.Graph(id="priority-graph")
                ])
            ])
        ], lg=6, md=12),
        
        # Alert Types
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-sitemap me-2"),
                    "Alert Types"
                ], className="d-flex align-items-center"),
                dbc.CardBody([
                    dcc.Graph(id="alert-types-graph")
                ])
            ])
        ], lg=6, md=12)
    ], className="mb-4"),
    
    # Data Tables with Tabs
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-table me-2"),
                    "Detailed Security Data"
                ], className="d-flex align-items-center"),
                dbc.CardBody([
                    dbc.Tabs([
                        # Failed Logins Tab
                        dbc.Tab([
                            dash_table.DataTable(
                                id="login-table",
                                columns=[{"name": col, "id": col} for col in login_df.columns] if not login_df.empty else [],
                                data=login_df.to_dict("records") if not login_df.empty else [],
                                page_size=10,
                                sort_action="native",
                                sort_mode="multi",
                                filter_action="native",
                                style_data_conditional=[
                                    {
                                        "if": {"filter_query": "{risk_score} >= 80"},
                                        "backgroundColor": "rgba(255, 0, 0, 0.2)",
                                        "color": "darkred",
                                        "fontWeight": "bold"
                                    }
                                ],
                                style_header={
                                    "backgroundColor": "rgb(230, 230, 230)",
                                    "fontWeight": "bold"
                                },
                                style_table={"overflowX": "auto"},
                                style_cell={
                                    "fontFamily": "Open Sans, sans-serif",
                                    "padding": "15px 5px",
                                    "textAlign": "left"
                                },
                                style_data={
                                    "whiteSpace": "normal",
                                    "height": "auto"
                                }
                            )
                        ], label="Failed Logins", tab_id="tab-logins", 
                           tab_style={"marginLeft": "0px"}, 
                           label_style={"color": "#dc3545", "fontWeight": "bold"}),
                        
                        # Suspicious Traffic Tab
                        dbc.Tab([
                            dash_table.DataTable(
                                id="traffic-table",
                                columns=[{"name": col, "id": col} for col in traffic_df.columns] if not traffic_df.empty else [],
                                data=traffic_df.to_dict("records") if not traffic_df.empty else [],
                                page_size=10,
                                sort_action="native",
                                sort_mode="multi",
                                filter_action="native",
                                style_data_conditional=[
                                    {
                                        "if": {"filter_query": "{anomaly_score} >= 80"},
                                        "backgroundColor": "rgba(255, 165, 0, 0.2)",
                                        "color": "darkred",
                                        "fontWeight": "bold"
                                    }
                                ],
                                style_header={
                                    "backgroundColor": "rgb(230, 230, 230)",
                                    "fontWeight": "bold"
                                },
                                style_table={"overflowX": "auto"},
                                style_cell={
                                    "fontFamily": "Open Sans, sans-serif",
                                    "padding": "15px 5px",
                                    "textAlign": "left"
                                },
                                style_data={
                                    "whiteSpace": "normal",
                                    "height": "auto"
                                }
                            )
                        ], label="Suspicious Traffic", tab_id="tab-traffic",
                           label_style={"color": "#ffc107", "fontWeight": "bold"}),
                        
                        # Security Alerts Tab
                        dbc.Tab([
                            dash_table.DataTable(
                                id="alerts-table",
                                columns=[{"name": col, "id": col} for col in alerts_df.columns] if not alerts_df.empty else [],
                                data=alerts_df.to_dict("records") if not alerts_df.empty else [],
                                page_size=10,
                                sort_action="native",
                                sort_mode="multi",
                                filter_action="native",
                                style_data_conditional=[
                                    {
                                        "if": {"filter_query": "{priority} eq \"CRITICAL\""},
                                        "backgroundColor": "rgba(255, 0, 0, 0.2)",
                                        "color": "darkred",
                                        "fontWeight": "bold"
                                    },
                                    {
                                        "if": {"filter_query": "{priority} eq \"HIGH\""},
                                        "backgroundColor": "rgba(255, 165, 0, 0.2)",
                                        "color": "darkorange",
                                        "fontWeight": "bold"
                                    }
                                ],
                                style_header={
                                    "backgroundColor": "rgb(230, 230, 230)",
                                    "fontWeight": "bold"
                                },
                                style_table={"overflowX": "auto"},
                                style_cell={
                                    "fontFamily": "Open Sans, sans-serif",
                                    "padding": "15px 5px",
                                    "textAlign": "left"
                                },
                                style_data={
                                    "whiteSpace": "normal",
                                    "height": "auto"
                                }
                            )
                        ], label="Security Alerts", tab_id="tab-alerts",
                           label_style={"color": "#17a2b8", "fontWeight": "bold"}),
                    ], id="tabs", active_tab="tab-logins")
                ])
            ])
        ], width=12)
    ]),
    
    # Footer with refresh button and timestamp
    dbc.Row([
        dbc.Col([
            html.Hr(),
            html.Div([
                dbc.Button([
                    html.I(className="fas fa-sync-alt me-2"),
                    "Refresh Data"
                ], id="refresh-button", color="primary", className="refresh-btn"),
                html.Span(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                          id="update-time", 
                          className="ms-3 dashboard-footer"),
                dcc.Interval(
                    id='interval-component',
                    interval=5*60*1000,  # 5 minutes in milliseconds
                    n_intervals=0
                )
            ], className="d-flex align-items-center justify-content-between mb-3")
        ], width=12)
    ])
], fluid=True, className="px-4 py-3")

# Define graph styles for consistency
graph_layout = {
    "margin": {"l": 40, "r": 40, "t": 40, "b": 40},
    "legend": {"orientation": "h", "y": -0.2},
    "plot_bgcolor": "rgba(0,0,0,0)",
    "paper_bgcolor": "rgba(0,0,0,0)",
    "font": {"family": "Open Sans, sans-serif", "size": 12},
    "height": 400
}

# Define callbacks to update graphs based on filters
@app.callback(
    [Output("risk-score-graph", "figure"),
     Output("anomaly-score-graph", "figure"),
     Output("priority-graph", "figure"),
     Output("alert-types-graph", "figure")],
    [Input("risk-range-slider", "value"),
     Input("priority-checklist", "value"),
     Input("refresh-button", "n_clicks"),
     Input("interval-component", "n_intervals")]
)
def update_graphs(risk_range, selected_priorities, n_clicks, n_intervals):
    # Get the most recent data
    latest_login, latest_traffic, latest_alerts = get_latest_files()
    
    login_df = pd.read_csv(latest_login) if latest_login else pd.DataFrame()
    traffic_df = pd.read_csv(latest_traffic) if latest_traffic else pd.DataFrame()
    alerts_df = pd.read_csv(latest_alerts) if latest_alerts else pd.DataFrame()
    
    # Risk Score Distribution
    if not login_df.empty:
        filtered_login_df = login_df[(login_df['risk_score'] >= risk_range[0]) & 
                                   (login_df['risk_score'] <= risk_range[1])]
        
        risk_counts = filtered_login_df.groupby('risk_score').size().reset_index(name='count')
        
        risk_fig = px.bar(
            risk_counts, 
            x='risk_score', 
            y='count', 
            title="Login Risk Distribution",
            labels={'risk_score': 'Risk Score', 'count': 'Number of Events'},
            color='risk_score',
            color_continuous_scale=px.colors.sequential.Reds,
            template="plotly_white"
        )
        risk_fig.update_layout(**graph_layout)
    else:
        risk_fig = go.Figure()
        risk_fig.update_layout(title="No Login Risk Data Available", **graph_layout)
    
    # Anomaly Score Distribution
    if not traffic_df.empty:
        anomaly_counts = traffic_df.groupby('anomaly_score').size().reset_index(name='count')
        
        anomaly_fig = px.bar(
            anomaly_counts, 
            x='anomaly_score', 
            y='count', 
            title="Traffic Anomaly Distribution",
            labels={'anomaly_score': 'Anomaly Score', 'count': 'Number of Events'},
            color='anomaly_score',
            color_continuous_scale=px.colors.sequential.Blues,
            template="plotly_white"
        )
        anomaly_fig.update_layout(**graph_layout)
    else:
        anomaly_fig = go.Figure()
        anomaly_fig.update_layout(title="No Traffic Anomaly Data Available", **graph_layout)
    
    # Priority Distribution
    if not alerts_df.empty:
        filtered_alerts_df = alerts_df[alerts_df['priority'].isin(selected_priorities)]
        
        priority_counts = filtered_alerts_df.groupby('priority').size().reset_index(name='count')
        
        # Create a custom sort order
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        priority_counts['sort_order'] = priority_counts['priority'].map(priority_order)
        priority_counts = priority_counts.sort_values('sort_order')
        
        # Create a color map
        color_map = {
            'CRITICAL': '#dc3545',  # Red
            'HIGH': '#fd7e14',      # Orange
            'MEDIUM': '#ffc107',    # Yellow
            'LOW': '#28a745'        # Green
        }
        
        priority_fig = px.pie(
            priority_counts, 
            values='count', 
            names='priority', 
            title="Alert Priority Distribution",
            color='priority',
            color_discrete_map=color_map,
            template="plotly_white",
            hole=0.4  # Create a donut chart
        )
        # Improve the pie chart
        priority_fig.update_traces(
            textposition='inside', 
            textinfo='percent+label',
            marker=dict(line=dict(color='white', width=2))
        )
        priority_fig.update_layout(**graph_layout)
    else:
        priority_fig = go.Figure()
        priority_fig.update_layout(title="No Alerts Data Available", **graph_layout)
    
    # Alert Types
    if not alerts_df.empty:
        filtered_alerts_df = alerts_df[alerts_df['priority'].isin(selected_priorities)]
        
        alert_type_counts = filtered_alerts_df.groupby('alert_type').size().reset_index(name='count')
        alert_type_counts = alert_type_counts.sort_values('count', ascending=False)
        
        alert_types_fig = px.bar(
            alert_type_counts, 
            x='count', 
            y='alert_type', 
            title="Alert Types",
            labels={'count': 'Number of Alerts', 'alert_type': 'Alert Type'},
            orientation='h',
            color='count',
            color_continuous_scale=px.colors.sequential.Viridis,
            template="plotly_white"
        )
        alert_types_fig.update_layout(**graph_layout)
    else:
        alert_types_fig = go.Figure()
        alert_types_fig.update_layout(title="No Alerts Data Available", **graph_layout)
    
    return risk_fig, anomaly_fig, priority_fig, alert_types_fig

# Callback to update tables when refreshing data
@app.callback(
    [Output("login-table", "data"),
     Output("login-table", "columns"),
     Output("traffic-table", "data"),
     Output("traffic-table", "columns"),
     Output("alerts-table", "data"),
     Output("alerts-table", "columns"),
     Output("update-time", "children")],
    [Input("refresh-button", "n_clicks"),
     Input("interval-component", "n_intervals")]
)
def update_tables(n_clicks, n_intervals):
    # Get the most recent data
    latest_login, latest_traffic, latest_alerts = get_latest_files()
    
    login_df = pd.read_csv(latest_login) if latest_login else pd.DataFrame()
    traffic_df = pd.read_csv(latest_traffic) if latest_traffic else pd.DataFrame()
    alerts_df = pd.read_csv(latest_alerts) if latest_alerts else pd.DataFrame()
    
    # Sort dataframes by important columns
    if not login_df.empty:
        login_df = login_df.sort_values('risk_score', ascending=False)
    
    if not traffic_df.empty:
        traffic_df = traffic_df.sort_values('anomaly_score', ascending=False)
    
    if not alerts_df.empty:
        alerts_df = alerts_df.sort_values(['severity_score', 'action_required'], ascending=[False, False])
    
    # Update timestamp
    current_time = f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    
    return (
        login_df.to_dict("records") if not login_df.empty else [],
        [{"name": col, "id": col} for col in login_df.columns] if not login_df.empty else [],
        traffic_df.to_dict("records") if not traffic_df.empty else [],
        [{"name": col, "id": col} for col in traffic_df.columns] if not traffic_df.empty else [],
        alerts_df.to_dict("records") if not alerts_df.empty else [],
        [{"name": col, "id": col} for col in alerts_df.columns] if not alerts_df.empty else [],
        current_time
    )

# Run the app
if __name__ == "__main__":
    app.run(debug=True, port=8050)