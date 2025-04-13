#!/usr/bin/env python3
"""
Cyber Security ETL Pipeline

This script demonstrates a complete ETL process for cybersecurity data:
1. Extract data from MySQL, PostgreSQL, and MongoDB
2. Transform the data (clean, filter, aggregate)
3. Load the results back to the databases and to files

Each team member will replace the database configuration in a .env file
to connect to their own databases.
"""

import os
import sys
import argparse
from datetime import datetime
import pandas as pd
import numpy as np
from dotenv import load_dotenv

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import utility modules
from utils.spark_utils import create_spark_session, stop_spark_session
from utils.db_connectors import (
    test_database_connections,
    read_table_from_mysql,
    read_table_from_postgres,
    read_collection_from_mongodb,
    write_dataframe_to_mysql,
    write_dataframe_to_postgres,
    write_dataframe_to_mongodb
)

# PySpark and SQL functions
from pyspark.sql import functions as F
from pyspark.sql.window import Window
from pyspark.sql.types import (
    StructType, StructField, StringType, IntegerType, 
    TimestampType, BooleanType, DoubleType
)


def setup_data_tables(spark, role):
    """
    Set up sample tables and collections for the ETL process
    based on team member role.
    
    Args:
        spark: Active Spark session
        role: Team member role (security, data, ml, llm)
    """
    print(f"\n{'='*20} Setting up sample data for role: {role} {'='*20}")
    
    # Define schema for login_attempts table
    print("\n📊 Defining schema for login_attempts table...")
    login_schema = StructType([
        StructField("attempt_id", IntegerType(), False),
        StructField("username", StringType(), True),
        StructField("timestamp", TimestampType(), True),
        StructField("ip_address", StringType(), True),
        StructField("success", BooleanType(), True),
        StructField("user_agent", StringType(), True),
        StructField("location", StringType(), True)
    ])
    
    # Generate sample login attempts data
    print("🔄 Generating sample login attempts data...")
    login_data = []
    for i in range(1, 101):
        success = i % 3 != 0  # Every 3rd login fails
        login_data.append((
            i,
            f"user{i % 10}",
            datetime.now(),
            f"192.168.1.{i % 255}",
            success,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "New York, USA" if i % 5 == 0 else "Los Angeles, USA"
        ))
    
    login_df = spark.createDataFrame(login_data, schema=login_schema)
    
    # Define schema for network_traffic table
    print("\n📊 Defining schema for network_traffic table...")
    traffic_schema = StructType([
        StructField("traffic_id", IntegerType(), False),
        StructField("source_ip", StringType(), True),
        StructField("destination_ip", StringType(), True),
        StructField("protocol", StringType(), True),
        StructField("port", IntegerType(), True),
        StructField("packet_size", IntegerType(), True),
        StructField("timestamp", TimestampType(), True),
        StructField("is_suspicious", BooleanType(), True)
    ])
    
    # Generate sample network traffic data
    print("🔄 Generating sample network traffic data...")
    traffic_data = []
    for i in range(1, 151):
        is_suspicious = i % 10 == 0  # Every 10th traffic is suspicious
        traffic_data.append((
            i,
            f"192.168.1.{i % 255}",
            f"10.0.0.{i % 255}",
            "TCP" if i % 3 == 0 else "UDP",
            80 if i % 4 == 0 else (443 if i % 4 == 1 else 22),
            (i % 10) * 100 + 100,
            datetime.now(),
            is_suspicious
        ))
    
    traffic_df = spark.createDataFrame(traffic_data, schema=traffic_schema)
    
    # Define schema for security_alerts collection
    print("\n📊 Defining schema for security_alerts collection...")
    alert_schema = StructType([
        StructField("alert_id", IntegerType(), False),
        StructField("alert_type", StringType(), True),
        StructField("severity", StringType(), True),
        StructField("timestamp", TimestampType(), True),
        StructField("source", StringType(), True),
        StructField("description", StringType(), True),
        StructField("affected_system", StringType(), True),
        StructField("is_resolved", BooleanType(), True)
    ])
    
    # Generate sample security alerts data
    print("🔄 Generating sample security alerts data...")
    alert_data = []
    for i in range(1, 81):
        severity = "HIGH" if i % 10 == 0 else ("MEDIUM" if i % 5 == 0 else "LOW")
        alert_data.append((
            i,
            "Brute Force" if i % 4 == 0 else ("Malware" if i % 4 == 1 else 
                                            ("Data Exfiltration" if i % 4 == 2 else "Privilege Escalation")),
            severity,
            datetime.now(),
            f"IDS-{i % 5}",
            f"Security alert detected on system {i % 20}",
            f"Server-{i % 10}",
            i % 3 == 0  # Every 3rd alert is resolved
        ))
    
    alert_df = spark.createDataFrame(alert_data, schema=alert_schema)
    
    # Write data to databases
    print("\n💾 Writing sample data to databases...")
    try:
        # MySQL
        print("⏳ Creating login_attempts table in MySQL...")
        login_df.write.jdbc(
            url=f"jdbc:mysql://{os.getenv('MYSQL_HOST')}:{os.getenv('MYSQL_PORT')}/{os.getenv('MYSQL_DB')}",
            table="login_attempts",
            mode="overwrite",
            properties={
                "user": os.getenv("MYSQL_USER"),
                "password": os.getenv("MYSQL_PASSWORD"),
                "driver": "com.mysql.cj.jdbc.Driver",
                "createTableOptions": "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
                "useSSL": "false"
            }
        )
        print("✅ Sample login_attempts table created in MySQL")
        
        # PostgreSQL
        print("⏳ Creating network_traffic table in PostgreSQL...")
        traffic_df.write.jdbc(
            url=f"jdbc:postgresql://{os.getenv('POSTGRES_HOST')}:{os.getenv('POSTGRES_PORT')}/{os.getenv('POSTGRES_DB')}",
            table="network_traffic",
            mode="overwrite",
            properties={
                "user": os.getenv("POSTGRES_USER"),
                "password": os.getenv("POSTGRES_PASSWORD"),
                "driver": "org.postgresql.Driver"
            }
        )
        print("✅ Sample network_traffic table created in PostgreSQL")
        
        # MongoDB - Convert to pandas and use pymongo directly since mongo-spark-connector can be finicky
        # This is a simpler approach for sample data generation
        print("⏳ Creating security_alerts collection in MongoDB...")
        alerts_pd = alert_df.toPandas()
        
        # Convert to list of dictionaries for MongoDB
        alerts_dict = alerts_pd.to_dict('records')
        
        # We'll write this to a file since MongoDB insert is done differently
        import json
        with open('sample_alerts.json', 'w') as f:
            json.dump(alerts_dict, f)
            
        print("✅ Sample security_alerts saved to sample_alerts.json")
        print("  - Use 'mongoimport' command to import this file to MongoDB")
        
    except Exception as e:
        print(f"❌ Error setting up sample data: {e}")


def safe_to_csv(df, output_path):
    """
    Safely convert a Spark DataFrame to CSV via Pandas.
    Handles datetime conversion issues.
    
    Args:
        df: Spark DataFrame to save
        output_path: Path to save the CSV file
    """
    # First convert any timestamp columns in Spark to strings to avoid pandas issues
    for col_name, col_type in df.dtypes:
        if 'timestamp' in col_type.lower():
            df = df.withColumn(col_name, df[col_name].cast('string'))
    
    # Now convert to pandas safely
    pandas_df = df.toPandas()
    
    # Write to CSV
    pandas_df.to_csv(output_path, index=False)
    
    return pandas_df


def extract_data(spark):
    """
    Extract data from all three databases.
    
    Args:
        spark: Active Spark session
    
    Returns:
        tuple: DataFrames from each source
    """
    print("\n" + "="*20 + " EXTRACT PHASE " + "="*20)
    print("🔍 Extracting data from all source databases...")
    
    # Extract login attempts from MySQL
    print("\n📥 Extracting login attempts from MySQL...")
    try:
        # Using SQL query for extraction
        login_query = """
        SELECT 
            attempt_id, username, timestamp, ip_address, success, user_agent, location
        FROM 
            login_attempts
        ORDER BY 
            timestamp DESC
        """
        
        login_attempts_df = read_table_from_mysql(spark, login_query, is_query=True)
        row_count = login_attempts_df.count()
        print(f"✅ Successfully extracted {row_count} rows from MySQL login_attempts table")
        print(f"   -> Sample columns: {', '.join(login_attempts_df.columns[:5])}...")
        
        # Display a sample of the data for verification
        if row_count > 0:
            print("   -> Sample data preview:")
            login_attempts_df.show(3, truncate=True)
            
    except Exception as e:
        print(f"❌ Error extracting from MySQL: {e}")
        login_attempts_df = spark.createDataFrame([], schema=StructType([]))
    
    # Extract network traffic from PostgreSQL
    print("\n📥 Extracting network traffic from PostgreSQL...")
    try:
        # Using SQL query for extraction
        traffic_query = """
        SELECT 
            traffic_id, source_ip, destination_ip, protocol, port, 
            packet_size, timestamp, is_suspicious
        FROM 
            network_traffic
        ORDER BY 
            timestamp DESC
        """
        
        network_traffic_df = read_table_from_postgres(spark, traffic_query, is_query=True)
        row_count = network_traffic_df.count()
        print(f"✅ Successfully extracted {row_count} rows from PostgreSQL network_traffic table")
        print(f"   -> Sample columns: {', '.join(network_traffic_df.columns[:5])}...")
        
        # Display a sample of the data for verification
        if row_count > 0:
            print("   -> Sample data preview:")
            network_traffic_df.show(3, truncate=True)
            
    except Exception as e:
        print(f"❌ Error extracting from PostgreSQL: {e}")
        network_traffic_df = spark.createDataFrame([], schema=StructType([]))
    
    # Extract security alerts from MongoDB
    print("\n📥 Extracting security alerts from MongoDB...")
    try:
        # Using MongoDB query equivalent
        security_alerts_df = read_collection_from_mongodb(spark, "security_alerts", 
                                                         query={"is_resolved": False})
        row_count = security_alerts_df.count()
        print(f"✅ Successfully extracted {row_count} documents from MongoDB security_alerts collection")
        
        if row_count > 0:
            print(f"   -> Sample columns: {', '.join(security_alerts_df.columns[:5])}...")
            print("   -> Sample data preview:")
            security_alerts_df.show(3, truncate=True)
            
    except Exception as e:
        print(f"❌ Error extracting from MongoDB: {e}")
        security_alerts_df = spark.createDataFrame([], schema=StructType([]))
    
    return login_attempts_df, network_traffic_df, security_alerts_df


def transform_data(login_attempts_df, network_traffic_df, security_alerts_df):
    """
    Transform the extracted data.
    
    Args:
        login_attempts_df: DataFrame with login attempts
        network_traffic_df: DataFrame with network traffic
        security_alerts_df: DataFrame with security alerts
    
    Returns:
        tuple: Transformed DataFrames
    """
    print("\n" + "="*20 + " TRANSFORM PHASE " + "="*20)
    print("🔧 Applying transformations to extracted data...")
    
    # 1. Transform login attempts data - Calculate failed login metrics
    print("\n🔄 Transforming login attempts data - Calculating failed login metrics...")
    if login_attempts_df.count() > 0:
        # Group by username and count failed attempts
        print("   -> Filtering for failed login attempts...")
        print("   -> Grouping by username and IP address...")
        print("   -> Calculating time spans and attempt frequencies...")
        print("   -> Computing risk scores based on attempt patterns...")
        
        failed_logins_df = (
            login_attempts_df
            .filter(~login_attempts_df.success)  # Filter for failed attempts
            .groupBy("username", "ip_address")
            .agg(
                F.count("*").alias("failed_attempt_count"),
                F.min("timestamp").alias("first_attempt"),
                F.max("timestamp").alias("last_attempt")
            )
            .withColumn("time_span_seconds", 
                        F.unix_timestamp("last_attempt") - F.unix_timestamp("first_attempt"))
            .withColumn("attempts_per_minute", 
                        F.expr("failed_attempt_count / (time_span_seconds / 60)"))
            .withColumn("risk_score", 
                        F.when(F.col("failed_attempt_count") >= 5, 
                              F.when(F.col("time_span_seconds") <= 60, 100)  # 5+ attempts in 1 minute
                              .when(F.col("time_span_seconds") <= 300, 80)   # 5+ attempts in 5 minutes
                              .when(F.col("time_span_seconds") <= 3600, 50)  # 5+ attempts in 1 hour
                              .otherwise(30))
                        .when(F.col("failed_attempt_count") >= 3, 20)
                        .otherwise(10))
            .orderBy(F.desc("risk_score"))
        )
        
        # Display a sample of the transformed data
        print("   -> Transformed data preview:")
        failed_logins_df.show(3, truncate=True)
        
        print(f"✅ Successfully transformed login attempts: {failed_logins_df.count()} failed login aggregates calculated")
        print("   -> Risk score distribution:")
        failed_logins_df.groupBy("risk_score").count().orderBy(F.desc("risk_score")).show(truncate=False)
        
    else:
        failed_logins_df = login_attempts_df
        print("⚠️ No login attempts data to transform")
    
    # 2. Transform network traffic data - Identify suspicious traffic patterns
    print("\n🔄 Transforming network traffic data - Identifying suspicious patterns...")
    if network_traffic_df.count() > 0:
        print("   -> Analyzing traffic patterns over time...")
        print("   -> Detecting rapid connections and suspicious ports...")
        print("   -> Computing anomaly scores based on multiple indicators...")
        
        # Define a window spec for analyzing traffic patterns over time
        window_spec = Window.partitionBy("source_ip").orderBy("timestamp")
        
        # Analyze traffic patterns
        suspicious_traffic_df = (
            network_traffic_df
            .withColumn("prev_timestamp", F.lag("timestamp", 1).over(window_spec))
            .withColumn("time_diff_seconds", 
                        F.when(F.col("prev_timestamp").isNotNull(),
                              F.unix_timestamp("timestamp") - F.unix_timestamp("prev_timestamp"))
                        .otherwise(None))
            .withColumn("rapid_connection", 
                        F.when(F.col("time_diff_seconds") < 1, True).otherwise(False))
            .withColumn("suspicious_port", 
                        F.when(F.col("port").isin(22, 3389, 445, 1433, 3306, 5432), True).otherwise(False))
            .withColumn("large_packet", 
                        F.when(F.col("packet_size") > 1000, True).otherwise(False))
            .withColumn("anomaly_score", 
                        F.when(F.col("is_suspicious"), 100)
                        .otherwise(
                            F.when(F.col("rapid_connection") & F.col("suspicious_port"), 80)
                            .when(F.col("rapid_connection") | F.col("suspicious_port"), 50)
                            .when(F.col("large_packet"), 30)
                            .otherwise(10)
                        ))
            .select(
                "traffic_id", "source_ip", "destination_ip", "protocol", "port", 
                "timestamp", "packet_size", "is_suspicious", "rapid_connection", 
                "suspicious_port", "large_packet", "anomaly_score"
            )
            .orderBy(F.desc("anomaly_score"))
        )
        
        # Display a sample of the transformed data
        print("   -> Transformed data preview:")
        suspicious_traffic_df.show(3, truncate=True)
        
        print(f"✅ Successfully transformed network traffic: {suspicious_traffic_df.count()} traffic records analyzed")
        print("   -> Anomaly score distribution:")
        suspicious_traffic_df.groupBy("anomaly_score").count().orderBy(F.desc("anomaly_score")).show(truncate=False)
        
    else:
        suspicious_traffic_df = network_traffic_df
        print("⚠️ No network traffic data to transform")
    
    # 3. Transform security alerts data - Prioritize and enrich alerts
    print("\n🔄 Transforming security alerts data - Prioritizing and enriching alerts...")
    if security_alerts_df.count() > 0:
        print("   -> Converting severity levels to numeric scores...")
        print("   -> Categorizing alerts by priority...")
        print("   -> Flagging alerts requiring immediate action...")
        
        # Enrich alerts with priority scores
        enriched_alerts_df = (
            security_alerts_df
            .withColumn("severity_score", 
                        F.when(F.col("severity") == "HIGH", 100)
                        .when(F.col("severity") == "MEDIUM", 50)
                        .when(F.col("severity") == "LOW", 20)
                        .otherwise(10))
            .withColumn("priority", 
                        F.when(F.col("severity_score") >= 80, "CRITICAL")
                        .when(F.col("severity_score") >= 50, "HIGH")
                        .when(F.col("severity_score") >= 20, "MEDIUM")
                        .otherwise("LOW"))
            .withColumn("action_required", 
                        F.when(~F.col("is_resolved") & (F.col("severity_score") >= 50), True)
                        .otherwise(False))
            .orderBy(F.desc("severity_score"), F.asc("is_resolved"))
        )
        
        # Display a sample of the transformed data
        print("   -> Transformed data preview:")
        enriched_alerts_df.show(3, truncate=True)
        
        print(f"✅ Successfully transformed security alerts: {enriched_alerts_df.count()} alerts enriched and prioritized")
        print("   -> Priority distribution:")
        enriched_alerts_df.groupBy("priority").count().orderBy(F.desc("count")).show(truncate=False)
        print("   -> Action required summary:")
        enriched_alerts_df.groupBy("action_required").count().show(truncate=False)
        
    else:
        enriched_alerts_df = security_alerts_df
        print("⚠️ No security alerts data to transform")
    
    return failed_logins_df, suspicious_traffic_df, enriched_alerts_df


def load_data(failed_logins_df, suspicious_traffic_df, enriched_alerts_df):
    """
    Load the transformed data back to databases and to output files.
    
    Args:
        failed_logins_df: DataFrame with failed login metrics
        suspicious_traffic_df: DataFrame with suspicious traffic analysis
        enriched_alerts_df: DataFrame with enriched security alerts
    """
    print("\n" + "="*20 + " LOAD PHASE " + "="*20)
    print("💾 Loading transformed data to destination systems...")
    
    # Create output directory if it doesn't exist
    output_dir = os.getenv("OUTPUT_PATH", "./output")
    os.makedirs(output_dir, exist_ok=True)
    
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 1. Load failed login metrics
    print("\n📤 Loading failed login metrics...")
    if failed_logins_df.count() > 0:
        try:
            # Save to MySQL
            print("   -> Writing to MySQL table 'failed_login_metrics'...")
            write_dataframe_to_mysql(
                failed_logins_df, 
                "failed_login_metrics", 
                mode="overwrite"
            )
            print("✅ Failed login metrics loaded to MySQL table 'failed_login_metrics'")
            
            # Save to CSV safely
            failed_logins_path = f"{output_dir}/failed_logins_{current_time}.csv"
            print(f"   -> Saving to CSV file at {failed_logins_path}...")
            
            # Use our safe method to convert Spark DataFrame to CSV
            pandas_df = safe_to_csv(failed_logins_df, failed_logins_path)
            
            print(f"✅ Failed login metrics saved to {failed_logins_path}")
            print(f"   -> File size: {os.path.getsize(failed_logins_path) / 1024:.2f} KB")
            print(f"   -> Rows: {len(pandas_df)}, Columns: {len(pandas_df.columns)}")
            
        except Exception as e:
            print(f"❌ Error loading failed login metrics: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("⚠️ No failed login metrics to load")
    
    # 2. Load suspicious traffic analysis
    print("\n📤 Loading suspicious traffic analysis...")
    if suspicious_traffic_df.count() > 0:
        try:
            # Save to PostgreSQL
            print("   -> Writing to PostgreSQL table 'suspicious_traffic_analysis'...")
            write_dataframe_to_postgres(
                suspicious_traffic_df, 
                "suspicious_traffic_analysis", 
                mode="overwrite"
            )
            print("✅ Suspicious traffic analysis loaded to PostgreSQL table 'suspicious_traffic_analysis'")
            
            # Save to CSV safely
            traffic_path = f"{output_dir}/suspicious_traffic_{current_time}.csv"
            print(f"   -> Saving to CSV file at {traffic_path}...")
            
            # Use our safe method to convert Spark DataFrame to CSV
            pandas_df = safe_to_csv(suspicious_traffic_df, traffic_path)
            
            print(f"✅ Suspicious traffic analysis saved to {traffic_path}")
            print(f"   -> File size: {os.path.getsize(traffic_path) / 1024:.2f} KB")
            print(f"   -> Rows: {len(pandas_df)}, Columns: {len(pandas_df.columns)}")
            
        except Exception as e:
            print(f"❌ Error loading suspicious traffic analysis: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("⚠️ No suspicious traffic analysis to load")
    
    # 3. Load enriched security alerts
    print("\n📤 Loading enriched security alerts...")
    if enriched_alerts_df.count() > 0:
        try:
            # Save to MongoDB
            print("   -> Writing to MongoDB collection 'enriched_security_alerts'...")
            write_dataframe_to_mongodb(
                enriched_alerts_df, 
                "enriched_security_alerts"
            )
            print("✅ Enriched security alerts loaded to MongoDB collection 'enriched_security_alerts'")
            
            # Save to CSV safely
            alerts_path = f"{output_dir}/enriched_alerts_{current_time}.csv"
            print(f"   -> Saving to CSV file at {alerts_path}...")
            
            # Use our safe method to convert Spark DataFrame to CSV
            pandas_df = safe_to_csv(enriched_alerts_df, alerts_path)
            
            print(f"✅ Enriched security alerts saved to {alerts_path}")
            print(f"   -> File size: {os.path.getsize(alerts_path) / 1024:.2f} KB")
            print(f"   -> Rows: {len(pandas_df)}, Columns: {len(pandas_df.columns)}")
            
        except Exception as e:
            print(f"❌ Error loading enriched security alerts: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("⚠️ No enriched security alerts to load")
    
    print(f"\n✅ All data has been processed and saved to {output_dir}")
    print(f"   -> Total files created: {len(os.listdir(output_dir))}")


def run_etl_pipeline():
    """
    Run the complete ETL pipeline.
    """
    start_time = datetime.now()
    
    # Load environment variables
    load_dotenv()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Cyber Security ETL Pipeline')
    parser.add_argument('--setup', action='store_true', help='Setup sample data tables')
    parser.add_argument('--role', type=str, choices=['security', 'data', 'ml', 'llm'], 
                        help='Team member role for sample data setup')
    parser.add_argument('--test-connections', action='store_true', help='Test database connections only')
    args = parser.parse_args()
    
    print("="*50)
    print("🚀 Cyber Security ETL Pipeline")
    print("="*50)
    print(f"⏱️  Started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📋 Running as user: {os.getenv('USER', 'unknown')}")
    
    # Create Spark session
    print("\n⚙️  Creating Spark session...")
    spark = create_spark_session()
    
    try:
        # Test connections if requested
        if args.test_connections:
            print("\n🔌 Testing database connections...")
            connection_status = test_database_connections()
            if all(connection_status.values()):
                print("\n✅ All database connections are successful!")
            else:
                print("\n⚠️ Some database connections failed. Please check your .env configuration.")
            return
        
        # Setup sample data if requested
        if args.setup:
            if not args.role:
                print("❌ Error: You must specify a role (--role) when using --setup")
                return
            setup_data_tables(spark, args.role)
            return
        
        # Run the ETL pipeline
        print("\n🔄 Starting ETL process...")
        
        # Extract phase
        login_attempts_df, network_traffic_df, security_alerts_df = extract_data(spark)
        
        # Transform phase
        failed_logins_df, suspicious_traffic_df, enriched_alerts_df = transform_data(
            login_attempts_df, network_traffic_df, security_alerts_df
        )
        
        # Load phase
        load_data(failed_logins_df, suspicious_traffic_df, enriched_alerts_df)
        
        # Summary
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        print("\n" + "="*50)
        print("📊 ETL Pipeline Summary")
        print("="*50)
        print(f"⏱️  Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"⏱️  Completed: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"⏱️  Duration: {duration:.2f} seconds")
        print("\n📈 Data Metrics:")
        print(f"   -> Login attempts extracted: {login_attempts_df.count()}")
        print(f"   -> Failed login metrics produced: {failed_logins_df.count()}")
        print(f"   -> Network traffic records extracted: {network_traffic_df.count()}")
        
        suspicious_count = 0
        if suspicious_traffic_df.count() > 0:
            suspicious_count = suspicious_traffic_df.filter(F.col('anomaly_score') > 50).count()
        print(f"   -> Suspicious traffic patterns detected: {suspicious_count}")
        
        print(f"   -> Security alerts processed: {security_alerts_df.count()}")
        
        critical_count = 0
        if enriched_alerts_df.count() > 0:
            critical_count = enriched_alerts_df.filter(F.col('priority').isin('CRITICAL', 'HIGH')).count()
        print(f"   -> Critical/High priority security issues: {critical_count}")
        
        print("\n✅ ETL Pipeline completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Error in ETL pipeline: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        # Stop Spark session
        print("\n⚙️  Stopping Spark session...")
        stop_spark_session(spark)


if __name__ == '__main__':
    run_etl_pipeline()