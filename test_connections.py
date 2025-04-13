#!/usr/bin/env python3
"""
Test database connections for the Cyber Security ETL project.
This script verifies connections to MySQL, PostgreSQL, and MongoDB.
"""

import os
import sys
from dotenv import load_dotenv
import pymysql
import psycopg2
from pymongo import MongoClient
from urllib.parse import quote_plus  # Add URL encoding

def test_mysql_connection():
    """Test connection to MySQL database"""
    print("\n--- Testing MySQL Connection ---")
    try:
        conn = pymysql.connect(
            host=os.getenv("MYSQL_HOST"),
            port=int(os.getenv("MYSQL_PORT", 3306)),
            user=os.getenv("MYSQL_USER"),
            password=os.getenv("MYSQL_PASSWORD"),
            database=os.getenv("MYSQL_DB"),
            # Add SSL configuration to avoid cryptography requirement
            ssl_disabled=True
        )
        
        # Test query
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        print(f"✅ MySQL connection successful!")
        print(f"  Host: {os.getenv('MYSQL_HOST')}")
        print(f"  User: {os.getenv('MYSQL_USER')}")
        print(f"  Database: {os.getenv('MYSQL_DB')}")
        print(f"  Test query result: {result}")
        
        return True
    except Exception as e:
        print(f"❌ MySQL connection failed: {e}")
        return False

def test_postgres_connection():
    """Test connection to PostgreSQL database"""
    print("\n--- Testing PostgreSQL Connection ---")
    try:
        conn = psycopg2.connect(
            host=os.getenv("POSTGRES_HOST"),
            port=int(os.getenv("POSTGRES_PORT", 5432)),
            user=os.getenv("POSTGRES_USER"),
            password=os.getenv("POSTGRES_PASSWORD"),
            dbname=os.getenv("POSTGRES_DB")
        )
        
        # Test query
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        print(f"✅ PostgreSQL connection successful!")
        print(f"  Host: {os.getenv('POSTGRES_HOST')}")
        print(f"  User: {os.getenv('POSTGRES_USER')}")
        print(f"  Database: {os.getenv('POSTGRES_DB')}")
        print(f"  Test query result: {result}")
        
        return True
    except Exception as e:
        print(f"❌ PostgreSQL connection failed: {e}")
        return False

def test_mongodb_connection():
    """Test connection to MongoDB database"""
    print("\n--- Testing MongoDB Connection ---")
    try:
        # URL encode username and password
        user = quote_plus(os.getenv('MONGO_USER'))
        password = quote_plus(os.getenv('MONGO_PASSWORD'))
        
        # Construct MongoDB URI with URL-encoded credentials
        mongo_uri = f"mongodb://{user}:{password}@{os.getenv('MONGO_HOST')}:{os.getenv('MONGO_PORT')}/{os.getenv('MONGO_DB')}?authSource={os.getenv('MONGO_AUTH_DB')}"
        
        # Connect to MongoDB
        client = MongoClient(mongo_uri)
        
        # Test connection by pinging the server
        result = client.admin.command('ping')
        
        # Try listing collections
        db = client[os.getenv('MONGO_DB')]
        collections = db.list_collection_names()
        
        client.close()
        
        print(f"✅ MongoDB connection successful!")
        print(f"  Host: {os.getenv('MONGO_HOST')}")
        print(f"  User: {os.getenv('MONGO_USER')} (URL-encoded)")
        print(f"  Database: {os.getenv('MONGO_DB')}")
        print(f"  Authentication DB: {os.getenv('MONGO_AUTH_DB')}")
        print(f"  Ping result: {result}")
        print(f"  Collections: {collections}")
        
        return True
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        return False

def show_env_vars():
    """Display current environment variables"""
    print("\n--- Current Environment Variables ---")
    print(f"MYSQL_HOST: {os.getenv('MYSQL_HOST')}")
    print(f"MYSQL_PORT: {os.getenv('MYSQL_PORT')}")
    print(f"MYSQL_USER: {os.getenv('MYSQL_USER')}")
    print(f"MYSQL_PASSWORD: {'*' * len(os.getenv('MYSQL_PASSWORD', '')) if os.getenv('MYSQL_PASSWORD') else 'Not set'}")
    print(f"MYSQL_DB: {os.getenv('MYSQL_DB')}")
    
    print(f"\nPOSTGRES_HOST: {os.getenv('POSTGRES_HOST')}")
    print(f"POSTGRES_PORT: {os.getenv('POSTGRES_PORT')}")
    print(f"POSTGRES_USER: {os.getenv('POSTGRES_USER')}")
    print(f"POSTGRES_PASSWORD: {'*' * len(os.getenv('POSTGRES_PASSWORD', '')) if os.getenv('POSTGRES_PASSWORD') else 'Not set'}")
    print(f"POSTGRES_DB: {os.getenv('POSTGRES_DB')}")
    
    print(f"\nMONGO_HOST: {os.getenv('MONGO_HOST')}")
    print(f"MONGO_PORT: {os.getenv('MONGO_PORT')}")
    print(f"MONGO_USER: {os.getenv('MONGO_USER')}")
    print(f"MONGO_PASSWORD: {'*' * len(os.getenv('MONGO_PASSWORD', '')) if os.getenv('MONGO_PASSWORD') else 'Not set'}")
    print(f"MONGO_DB: {os.getenv('MONGO_DB')}")
    print(f"MONGO_AUTH_DB: {os.getenv('MONGO_AUTH_DB')}")

def main():
    """Main function to test all database connections"""
    print("=" * 50)
    print("Database Connection Tests")
    print("=" * 50)
    
    # Load environment variables
    load_dotenv()
    
    # Show current environment variables
    show_env_vars()
    
    # Test connections
    mysql_ok = test_mysql_connection()
    postgres_ok = test_postgres_connection()
    mongo_ok = test_mongodb_connection()
    
    # Summary
    print("\n" + "=" * 50)
    print("Connection Test Summary")
    print("=" * 50)
    print(f"MySQL: {'✅ Success' if mysql_ok else '❌ Failed'}")
    print(f"PostgreSQL: {'✅ Success' if postgres_ok else '❌ Failed'}")
    print(f"MongoDB: {'✅ Success' if mongo_ok else '❌ Failed'}")
    
    if mysql_ok and postgres_ok and mongo_ok:
        print("\n✅ All connections successful! You're ready to run the ETL pipeline.")
        return 0
    else:
        print("\n⚠️ Some connections failed. Please check your .env configuration.")
        return 1

if __name__ == "__main__":
    sys.exit(main())