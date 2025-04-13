# Cyber Security ETL Pipeline and Dashboard

A cybersecurity data processing and visualization system that extracts security data from multiple database sources, transforms it with advanced analytics, and loads the results to both databases and visualization dashboards.

## 📋 Project Overview

This project provides an end-to-end pipeline for processing and analyzing cybersecurity data:

1. **Extract**: Pull security-related data from multiple database sources (MySQL, PostgreSQL, MongoDB)
2. **Transform**: Process and analyze the data to identify security patterns, risks, and anomalies
3. **Load**: Store processed data back to databases and make it available for visualization
4. **Visualize**: Present security insights through an interactive dashboard

## 🔧 Architecture

The system consists of several interconnected components:

- **ETL Pipeline**: PySpark-based data processing system
- **Database Connectors**: Interfaces to various database systems
- **Data Visualization**: Dash/Plotly-based security dashboard
- **Data Generation**: Utilities to populate test data

## 🧩 Components

### ETL Pipeline (`etl_pipeline.py`)

The core data processing engine that:
- Extracts data from multiple sources
- Applies security analytics to identify threats
- Loads processed data to destination systems

### Security Dashboard (`dash_dashboard.py`)

An interactive web dashboard that displays:
- Failed login metrics and patterns
- Suspicious traffic analysis
- Security alerts prioritization
- Real-time monitoring capabilities

### Database Utilities

- `db_connectors.py`: Database connection and operation utilities
- `spark_utils.py`: Spark session management utilities
- `test_connections.py`: Database connection testing tool

### Data Generation

- `populate_data.py`: Generates sample security data across databases

## 📊 Key Features

- **Multi-source Data Integration**: Combines security data from various systems
- **Risk Scoring**: Calculates risk scores for login attempts
- **Anomaly Detection**: Identifies suspicious traffic patterns
- **Alert Prioritization**: Ranks security alerts by severity
- **Real-time Monitoring**: Dashboard with auto-refresh capabilities
- **Interactive Filtering**: User-controlled data filtering in the dashboard

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- PySpark and Java JDK 8+
- MySQL, PostgreSQL, and MongoDB databases
- Required Python libraries (see `requirements.txt`)

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/prakash-aryan/cyber-security-etl.git
   cd cyber-security-etl
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Configure database connections:
   - Copy `.env.template` to `.env`
   - Update the values with your database credentials

### Database Setup

Run the following command to create the required database tables and populate them with sample data:

```
python populate_data.py
```

### Running the ETL Pipeline

To execute the full ETL process:

```
python etl_pipeline.py
```

For testing database connections only:

```
python etl_pipeline.py --test-connections
```

For setting up sample data for specific roles:

```
python etl_pipeline.py --setup --role=security
```

### Launching the Dashboard

To start the security dashboard:

```
python dash_dashboard.py
```

Then open your browser to `http://localhost:8050` to view the dashboard.

## 🔄 Data Flow

1. Raw security data is collected in source databases:
   - Login attempts in MySQL
   - Network traffic in PostgreSQL
   - Security alerts in MongoDB

2. The ETL pipeline processes this data to:
   - Calculate login risk scores
   - Identify suspicious traffic patterns
   - Prioritize security alerts

3. Processed data is stored in:
   - CSV files for portability
   - Destination database tables for persistence

4. The dashboard visualizes insights from processed data

## 🛡️ Project Roles

This project is designed to support multiple security team roles:

### Security & Database Engineer
- Focus: Traditional security analysis and database handling
- Works with rule-based detection systems

### Data Infrastructure Engineer
- Focus: Building the monitoring system and data pipelines
- Handles real-time log processing

### ML Engineer
- Focus: Developing machine learning models for threat detection
- Builds anomaly detection systems

### LLM Engineer
- Focus: Generating realistic security data using LLMs
- Creates diverse security scenarios for testing

## 📁 Directory Structure

```
cyber_security_etl/
├── dash_dashboard.py          # Security visualization dashboard
├── etl_pipeline.py            # Main ETL processing pipeline
├── populate_data.py           # Sample data generation utility
├── test_connections.py        # Database connection testing
├── .env                       # Configuration variables (not in repo)
├── .env.template              # Template for configuration
├── requirements.txt           # Python dependencies
├── output/                    # Output data directory
└── utils/                     # Utility modules
    ├── db_connectors.py       # Database connection utilities
    ├── spark_utils.py         # Spark session utilities
    └── __init__.py            # Package initialization
```

## ⚙️ Configuration

Copy the `.env.template` file to `.env` and update with your database credentials:

```
# Database Configurations
# MySQL Configuration
MYSQL_HOST=your_mysql_host
MYSQL_PORT=3306
MYSQL_USER=your_username
MYSQL_PASSWORD=your_password
MYSQL_DB=your_database

# PostgreSQL Configuration
POSTGRES_HOST=your_postgres_host
POSTGRES_PORT=5432
POSTGRES_USER=your_username
POSTGRES_PASSWORD=your_password
POSTGRES_DB=your_database

# MongoDB Configuration
MONGO_HOST=your_mongo_host
MONGO_PORT=27017
MONGO_USER=your_username
MONGO_PASSWORD=your_password
MONGO_DB=your_database
MONGO_AUTH_DB=your_auth_database

# Spark Configuration
SPARK_MASTER=local[*]
SPARK_APP_NAME=CyberSecurityETL
SPARK_LOG_LEVEL=ERROR

# Output Path for ETL Results
OUTPUT_PATH=./output
```

## 🧪 Testing

To test database connections:

```
python test_connections.py
```

## 📚 Additional Resources

- [PySpark Documentation](https://spark.apache.org/docs/latest/api/python/index.html)
- [Dash Documentation](https://dash.plotly.com/)
- [Plotly Documentation](https://plotly.com/python/)

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.