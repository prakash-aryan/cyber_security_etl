#!/usr/bin/env python3
"""
Populate Databases with Sample Data

This script creates tables/collections and populates them with sample data
for the Cyber Security ETL project.
"""

import os
import sys
import random
import datetime
import uuid
import pymysql
import psycopg2
from pymongo import MongoClient
from dotenv import load_dotenv
from urllib.parse import quote_plus
import ipaddress
import time

# Load environment variables
load_dotenv()

# Sample data constants
IP_RANGES = [
    "192.168.1.0/24",  # Internal network
    "10.0.0.0/24",     # Internal network
    "172.16.0.0/24",   # Internal network
    "203.0.113.0/24",  # External network (TEST-NET-3)
    "198.51.100.0/24", # External network (TEST-NET-2)
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
]

LOCATIONS = [
    "New York, USA",
    "Los Angeles, USA",
    "London, UK",
    "Toronto, Canada",
    "Sydney, Australia",
    "Tokyo, Japan",
    "Berlin, Germany",
    "Mumbai, India",
    "Beijing, China",
    "Moscow, Russia",
]

PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "SMTP", "SSH", "FTP"]

ALERT_TYPES = [
    "Brute Force",
    "SQL Injection",
    "Cross-Site Scripting",
    "Privilege Escalation",
    "Data Exfiltration",
    "Malware Detected",
    "Ransomware",
    "DDoS Attack",
    "Phishing Attempt",
    "Suspicious Login",
]

USERNAMES = [
    "admin", "user1", "jsmith", "agarcia", "mwilliams", "ljones", 
    "root", "system", "guest", "developer", "jenkins", "operator", 
    "analyst", "support", "helpdesk", "security"
]

def generate_random_ip(ip_range):
    """Generate a random IP address within the given range"""
    network = ipaddress.ip_network(ip_range)
    # Get a random host address from the network
    host_address = random.randint(0, network.num_addresses - 1)
    return str(network[host_address])

def generate_random_timestamp(days_back=30):
    """Generate a random timestamp within the past X days"""
    now = datetime.datetime.now()
    delta = datetime.timedelta(
        days=random.randint(0, days_back),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59)
    )
    return now - delta

def generate_timestamp_string(timestamp):
    """Convert timestamp to MySQL/PostgreSQL compatible string"""
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")

def create_mysql_tables():
    """Create tables in MySQL database"""
    print("\n--- Creating MySQL Tables ---")
    conn = None
    try:
        # Connect to MySQL
        conn = pymysql.connect(
            host=os.getenv("MYSQL_HOST"),
            port=int(os.getenv("MYSQL_PORT", 3306)),
            user=os.getenv("MYSQL_USER"),
            password=os.getenv("MYSQL_PASSWORD"),
            database=os.getenv("MYSQL_DB"),
            ssl_disabled=True
        )
        
        cursor = conn.cursor()
        
        # Create login_attempts table
        print("Creating login_attempts table...")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            attempt_id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) NOT NULL,
            timestamp DATETIME NOT NULL,
            ip_address VARCHAR(50) NOT NULL,
            success BOOLEAN NOT NULL,
            user_agent VARCHAR(500),
            location VARCHAR(100)
        )
        """)
        
        # Create failed_login_metrics table
        print("Creating failed_login_metrics table...")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS failed_login_metrics (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) NOT NULL,
            ip_address VARCHAR(50) NOT NULL,
            failed_attempt_count INT NOT NULL,
            first_attempt DATETIME NOT NULL,
            last_attempt DATETIME NOT NULL,
            time_span_seconds INT NOT NULL,
            attempts_per_minute FLOAT NOT NULL,
            risk_score INT NOT NULL
        )
        """)
        
        conn.commit()
        print("✅ MySQL tables created successfully")
        
    except Exception as e:
        print(f"❌ Error creating MySQL tables: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

def create_postgres_tables():
    """Create tables in PostgreSQL database"""
    print("\n--- Creating PostgreSQL Tables ---")
    conn = None
    try:
        # Connect to PostgreSQL
        conn = psycopg2.connect(
            host=os.getenv("POSTGRES_HOST"),
            port=int(os.getenv("POSTGRES_PORT", 5432)),
            user=os.getenv("POSTGRES_USER"),
            password=os.getenv("POSTGRES_PASSWORD"),
            dbname=os.getenv("POSTGRES_DB")
        )
        
        conn.autocommit = True
        cursor = conn.cursor()
        
        # Create network_traffic table
        print("Creating network_traffic table...")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_traffic (
            traffic_id SERIAL PRIMARY KEY,
            source_ip VARCHAR(50) NOT NULL,
            destination_ip VARCHAR(50) NOT NULL,
            protocol VARCHAR(50) NOT NULL,
            port INT NOT NULL,
            packet_size INT NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            is_suspicious BOOLEAN NOT NULL
        )
        """)
        
        # Create suspicious_traffic_analysis table
        print("Creating suspicious_traffic_analysis table...")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS suspicious_traffic_analysis (
            analysis_id SERIAL PRIMARY KEY,
            traffic_id INT NOT NULL,
            source_ip VARCHAR(50) NOT NULL,
            destination_ip VARCHAR(50) NOT NULL,
            protocol VARCHAR(50) NOT NULL,
            port INT NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            packet_size INT NOT NULL,
            is_suspicious BOOLEAN NOT NULL,
            rapid_connection BOOLEAN,
            suspicious_port BOOLEAN,
            large_packet BOOLEAN,
            anomaly_score INT NOT NULL
        )
        """)
        
        print("✅ PostgreSQL tables created successfully")
        
    except Exception as e:
        print(f"❌ Error creating PostgreSQL tables: {e}")
    finally:
        if conn:
            conn.close()

def create_mongodb_collections():
    """Create collections in MongoDB database"""
    print("\n--- Creating MongoDB Collections ---")
    try:
        # URL encode credentials
        user = quote_plus(os.getenv('MONGO_USER'))
        password = quote_plus(os.getenv('MONGO_PASSWORD'))
        
        # Connect to MongoDB
        mongo_uri = f"mongodb://{user}:{password}@{os.getenv('MONGO_HOST')}:{os.getenv('MONGO_PORT')}/{os.getenv('MONGO_DB')}?authSource={os.getenv('MONGO_AUTH_DB')}"
        client = MongoClient(mongo_uri)
        db = client[os.getenv('MONGO_DB')]
        
        # Create security_alerts collection (MongoDB creates collections automatically when inserting)
        print("✅ MongoDB ready for data population")
        
        client.close()
        
    except Exception as e:
        print(f"❌ Error setting up MongoDB: {e}")

def populate_mysql_data(num_records=100):
    """Populate MySQL with sample login attempts data"""
    print("\n--- Populating MySQL with Sample Data ---")
    conn = None
    try:
        # Connect to MySQL
        conn = pymysql.connect(
            host=os.getenv("MYSQL_HOST"),
            port=int(os.getenv("MYSQL_PORT", 3306)),
            user=os.getenv("MYSQL_USER"),
            password=os.getenv("MYSQL_PASSWORD"),
            database=os.getenv("MYSQL_DB"),
            ssl_disabled=True
        )
        
        cursor = conn.cursor()
        
        # Clear existing data
        cursor.execute("TRUNCATE TABLE login_attempts")
        
        # Generate sample login attempts
        print(f"Generating {num_records} login attempt records...")
        
        # Create records with patterns for security analysis
        insert_query = """
        INSERT INTO login_attempts (username, timestamp, ip_address, success, user_agent, location)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        
        records = []
        
        # Normal successful logins
        for i in range(int(num_records * 0.7)):  # 70% successful logins
            username = random.choice(USERNAMES)
            timestamp = generate_timestamp_string(generate_random_timestamp())
            ip_address = generate_random_ip(random.choice(IP_RANGES[:3]))  # Internal IP
            success = True
            user_agent = random.choice(USER_AGENTS)
            location = random.choice(LOCATIONS[:5])  # Common locations
            
            records.append((username, timestamp, ip_address, success, user_agent, location))
        
        # Failed login attempts (including suspicious patterns)
        for i in range(int(num_records * 0.3)):  # 30% failed logins
            username = random.choice(USERNAMES)
            timestamp = generate_timestamp_string(generate_random_timestamp())
            
            # Some failures from external IPs (potentially suspicious)
            if random.random() < 0.4:
                ip_address = generate_random_ip(random.choice(IP_RANGES[3:]))  # External IP
            else:
                ip_address = generate_random_ip(random.choice(IP_RANGES[:3]))  # Internal IP
                
            success = False
            user_agent = random.choice(USER_AGENTS)
            
            # Some failures from unusual locations (potentially suspicious)
            if random.random() < 0.3:
                location = random.choice(LOCATIONS[5:])  # Less common locations
            else:
                location = random.choice(LOCATIONS[:5])  # Common locations
            
            records.append((username, timestamp, ip_address, success, user_agent, location))
        
        # Create clusters of failed login attempts (brute force pattern)
        # Add 5 groups of 5-10 rapid login failures
        for _ in range(5):
            username = random.choice(["admin", "root", "system"])  # Target privileged accounts
            base_time = generate_random_timestamp()
            ip_address = generate_random_ip(random.choice(IP_RANGES))
            user_agent = random.choice(USER_AGENTS)
            location = random.choice(LOCATIONS)
            
            # Generate 5-10 attempts within a short timeframe
            for i in range(random.randint(5, 10)):
                # Add a small time increment (seconds)
                timestamp = base_time + datetime.timedelta(seconds=i*10)
                success = False
                records.append((username, generate_timestamp_string(timestamp), ip_address, success, user_agent, location))
        
        # Insert all records
        cursor.executemany(insert_query, records)
        conn.commit()
        
        print(f"✅ {len(records)} sample login records inserted into MySQL")
        
    except Exception as e:
        print(f"❌ Error populating MySQL data: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

def populate_postgres_data(num_records=150):
    """Populate PostgreSQL with sample network traffic data"""
    print("\n--- Populating PostgreSQL with Sample Data ---")
    conn = None
    try:
        # Connect to PostgreSQL
        conn = psycopg2.connect(
            host=os.getenv("POSTGRES_HOST"),
            port=int(os.getenv("POSTGRES_PORT", 5432)),
            user=os.getenv("POSTGRES_USER"),
            password=os.getenv("POSTGRES_PASSWORD"),
            dbname=os.getenv("POSTGRES_DB")
        )
        
        conn.autocommit = True
        cursor = conn.cursor()
        
        # Clear existing data
        cursor.execute("TRUNCATE TABLE network_traffic")
        
        # Generate sample network traffic
        print(f"Generating {num_records} network traffic records...")
        
        insert_query = """
        INSERT INTO network_traffic 
        (source_ip, destination_ip, protocol, port, packet_size, timestamp, is_suspicious)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        
        records = []
        
        # Common ports and their suspiciousness
        common_ports = {
            80: False,   # HTTP
            443: False,  # HTTPS
            53: False,   # DNS
            25: False,   # SMTP
            110: False,  # POP3
            143: False,  # IMAP
            22: True,    # SSH (could be suspicious)
            3389: True,  # RDP (could be suspicious)
            1433: True,  # MSSQL (could be suspicious)
            3306: True,  # MySQL (could be suspicious)
            445: True,   # SMB (could be suspicious)
            21: True,    # FTP (plain text, could be suspicious)
        }
        
        # Generate normal traffic (70%)
        for i in range(int(num_records * 0.7)):
            source_ip = generate_random_ip(random.choice(IP_RANGES[:3]))  # Internal source
            
            # Determine if traffic is internal or external
            if random.random() < 0.4:  # 40% chance of external traffic
                destination_ip = generate_random_ip(random.choice(IP_RANGES[3:]))
            else:
                destination_ip = generate_random_ip(random.choice(IP_RANGES[:3]))
            
            protocol = random.choice(PROTOCOLS)
            
            # Select common ports for normal traffic
            common_port_list = [p for p, is_suspicious in common_ports.items() if not is_suspicious]
            port = random.choice(common_port_list)
            
            packet_size = random.randint(64, 1500)  # Normal packet sizes
            timestamp = generate_timestamp_string(generate_random_timestamp())
            is_suspicious = False
            
            records.append((source_ip, destination_ip, protocol, port, packet_size, timestamp, is_suspicious))
        
        # Generate suspicious traffic (30%)
        for i in range(int(num_records * 0.3)):
            # Some suspicious traffic from external sources
            if random.random() < 0.6:
                source_ip = generate_random_ip(random.choice(IP_RANGES[3:]))  # External source
                destination_ip = generate_random_ip(random.choice(IP_RANGES[:3]))  # Internal destination
            else:
                source_ip = generate_random_ip(random.choice(IP_RANGES[:3]))  # Internal source
                destination_ip = generate_random_ip(random.choice(IP_RANGES[:3]))  # Internal destination
            
            protocol = random.choice(PROTOCOLS)
            
            # Select potentially suspicious ports
            suspicious_port_list = [p for p, is_suspicious in common_ports.items() if is_suspicious]
            port = random.choice(suspicious_port_list)
            
            # Some unusual packet sizes (could be data exfiltration)
            if random.random() < 0.3:
                packet_size = random.randint(5000, 20000)  # Unusually large packets
            else:
                packet_size = random.randint(64, 1500)
                
            timestamp = generate_timestamp_string(generate_random_timestamp())
            is_suspicious = True
            
            records.append((source_ip, destination_ip, protocol, port, packet_size, timestamp, is_suspicious))
        
        # Add clusters of suspicious traffic (potential scan or attack)
        # Generate 5 clusters of suspicious traffic
        for _ in range(5):
            source_ip = generate_random_ip(random.choice(IP_RANGES[3:]))  # External source
            destination_ip = generate_random_ip(random.choice(IP_RANGES[:3]))  # Internal target
            protocol = "TCP"  # Most scans use TCP
            
            base_time = generate_random_timestamp()
            
            # Generate rapid port scan pattern
            for i in range(random.randint(5, 15)):
                port = random.randint(20, 10000)  # Wide range of ports
                packet_size = random.randint(40, 100)  # Small packets typical for scans
                timestamp = base_time + datetime.timedelta(seconds=i)
                is_suspicious = True
                
                records.append((source_ip, destination_ip, protocol, port, packet_size, 
                                generate_timestamp_string(timestamp), is_suspicious))
        
        # Insert all records
        cursor.executemany(insert_query, records)
        
        print(f"✅ {len(records)} sample network traffic records inserted into PostgreSQL")
        
    except Exception as e:
        print(f"❌ Error populating PostgreSQL data: {e}")
    finally:
        if conn:
            conn.close()

def populate_mongodb_data(num_records=80):
    """Populate MongoDB with sample security alerts data"""
    print("\n--- Populating MongoDB with Sample Data ---")
    try:
        # URL encode credentials
        user = quote_plus(os.getenv('MONGO_USER'))
        password = quote_plus(os.getenv('MONGO_PASSWORD'))
        
        # Connect to MongoDB
        mongo_uri = f"mongodb://{user}:{password}@{os.getenv('MONGO_HOST')}:{os.getenv('MONGO_PORT')}/{os.getenv('MONGO_DB')}?authSource={os.getenv('MONGO_AUTH_DB')}"
        client = MongoClient(mongo_uri)
        db = client[os.getenv('MONGO_DB')]
        
        # Clear existing collection
        db.security_alerts.drop()
        
        # Create security alerts collection
        alerts_collection = db.security_alerts
        
        print(f"Generating {num_records} security alert records...")
        
        alerts = []
        
        # Generate alerts with different severities
        severity_distribution = {
            "LOW": 0.5,      # 50% low severity
            "MEDIUM": 0.3,   # 30% medium severity
            "HIGH": 0.2      # 20% high severity
        }
        
        for i in range(num_records):
            # Determine severity based on distribution
            severity_rand = random.random()
            if severity_rand < severity_distribution["LOW"]:
                severity = "LOW"
            elif severity_rand < severity_distribution["LOW"] + severity_distribution["MEDIUM"]:
                severity = "MEDIUM"
            else:
                severity = "HIGH"
            
            # Create alert document
            alert = {
                "alert_id": i + 1,
                "alert_type": random.choice(ALERT_TYPES),
                "severity": severity,
                "timestamp": generate_random_timestamp(),
                "source": f"IDS-{random.randint(1, 5)}",
                "description": f"Security alert detected: {random.choice(ALERT_TYPES)} on system {random.randint(1, 20)}",
                "affected_system": f"Server-{random.randint(1, 10)}",
                "is_resolved": random.random() < 0.6,  # 60% resolved
                "detection_details": {
                    "ip_address": generate_random_ip(random.choice(IP_RANGES)),
                    "username": random.choice(USERNAMES) if random.random() < 0.7 else None,
                    "port": random.randint(20, 65535) if random.random() < 0.8 else None,
                    "protocol": random.choice(PROTOCOLS) if random.random() < 0.8 else None
                }
            }
            
            alerts.append(alert)
        
        # Create clusters of related alerts (for pattern detection)
        # Generate 3 incident clusters with related alerts
        for incident_id in range(3):
            base_time = generate_random_timestamp()
            source_ip = generate_random_ip(random.choice(IP_RANGES))
            affected_system = f"Server-{random.randint(1, 5)}"
            
            # Incident progression (typically 4-6 steps in an attack)
            attack_steps = random.randint(4, 6)
            
            for step in range(attack_steps):
                # Create realistic attack sequence
                if step == 0:
                    alert_type = "Brute Force"
                    severity = "MEDIUM"
                    description = f"Multiple failed login attempts detected on {affected_system}"
                elif step == 1:
                    alert_type = "Suspicious Login"
                    severity = "MEDIUM" 
                    description = f"Successful login after multiple failures on {affected_system}"
                elif step == 2:
                    alert_type = "Privilege Escalation"
                    severity = "HIGH"
                    description = f"User attempting to gain admin privileges on {affected_system}"
                elif step == 3:
                    alert_type = "Data Exfiltration"
                    severity = "HIGH"
                    description = f"Unusual data transfer detected from {affected_system}"
                else:
                    alert_type = random.choice(["Malware Detected", "Ransomware"])
                    severity = "HIGH"
                    description = f"{alert_type} on {affected_system}"
                
                timestamp = base_time + datetime.timedelta(minutes=step*15)  # Steps 15 minutes apart
                
                alert = {
                    "alert_id": len(alerts) + 1,
                    "alert_type": alert_type,
                    "severity": severity,
                    "timestamp": timestamp,
                    "source": f"IDS-{random.randint(1, 5)}",
                    "description": description,
                    "affected_system": affected_system,
                    "is_resolved": step < (attack_steps - 2),  # Only the last couple alerts unresolved
                    "detection_details": {
                        "ip_address": source_ip,
                        "username": random.choice(USERNAMES),
                        "incident_id": f"INC-2024-{1000 + incident_id}",  # Link related alerts
                        "step": step + 1
                    }
                }
                
                alerts.append(alert)
        
        # Insert all alerts
        if alerts:
            alerts_collection.insert_many(alerts)
            
        print(f"✅ {len(alerts)} sample security alert records inserted into MongoDB")
        
        client.close()
        
    except Exception as e:
        print(f"❌ Error populating MongoDB data: {e}")

def main():
    """Main function to create and populate database tables"""
    print("=" * 50)
    print("Cyber Security Sample Data Generation")
    print("=" * 50)
    
    start_time = time.time()
    
    # Create database tables/collections
    create_mysql_tables()
    create_postgres_tables()
    create_mongodb_collections()
    
    # Populate with sample data
    populate_mysql_data(100)  # 100 login attempts
    populate_postgres_data(150)  # 150 network traffic records
    populate_mongodb_data(80)  # 80 security alerts
    
    end_time = time.time()
    duration = end_time - start_time
    
    print("\n" + "=" * 50)
    print(f"Data Population Completed in {duration:.2f} seconds")
    print("=" * 50)
    print("\nYou can now run the ETL pipeline:\n  python etl_pipeline.py")

if __name__ == "__main__":
    main()