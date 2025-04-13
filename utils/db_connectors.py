import os
from pyspark.sql import SparkSession
import pymysql
import psycopg2
from pymongo import MongoClient
from dotenv import load_dotenv
from urllib.parse import quote_plus

# Load environment variables
load_dotenv()

def get_mysql_jdbc_url():
    """
    Get MySQL JDBC URL from environment variables.
    
    Returns:
        tuple: (JDBC URL, connection properties dictionary)
    """
    host = os.getenv("MYSQL_HOST")
    port = os.getenv("MYSQL_PORT", "3306")
    user = os.getenv("MYSQL_USER")
    password = os.getenv("MYSQL_PASSWORD")
    db = os.getenv("MYSQL_DB")
    
    # Validate required parameters
    if not all([host, user, password, db]):
        missing = []
        if not host: missing.append("MYSQL_HOST")
        if not user: missing.append("MYSQL_USER")
        if not password: missing.append("MYSQL_PASSWORD")
        if not db: missing.append("MYSQL_DB")
        raise ValueError(f"Missing required MySQL environment variables: {', '.join(missing)}")
    
    # Create JDBC URL
    jdbc_url = f"jdbc:mysql://{host}:{port}/{db}"
    
    # Connection properties
    connection_properties = {
        "user": user,
        "password": password,
        "driver": "com.mysql.cj.jdbc.Driver",
        "useSSL": "false"
    }
    
    return jdbc_url, connection_properties


def get_postgres_jdbc_url():
    """
    Get PostgreSQL JDBC URL from environment variables.
    
    Returns:
        tuple: (JDBC URL, connection properties dictionary)
    """
    host = os.getenv("POSTGRES_HOST")
    port = os.getenv("POSTGRES_PORT", "5432")
    user = os.getenv("POSTGRES_USER")
    password = os.getenv("POSTGRES_PASSWORD")
    db = os.getenv("POSTGRES_DB")
    
    # Validate required parameters
    if not all([host, user, password, db]):
        missing = []
        if not host: missing.append("POSTGRES_HOST")
        if not user: missing.append("POSTGRES_USER")
        if not password: missing.append("POSTGRES_PASSWORD")
        if not db: missing.append("POSTGRES_DB")
        raise ValueError(f"Missing required PostgreSQL environment variables: {', '.join(missing)}")
    
    # Create JDBC URL
    jdbc_url = f"jdbc:postgresql://{host}:{port}/{db}"
    
    # Connection properties
    connection_properties = {
        "user": user,
        "password": password,
        "driver": "org.postgresql.Driver"
    }
    
    return jdbc_url, connection_properties


def test_database_connections():
    """
    Test connections to all three databases (MySQL, PostgreSQL, MongoDB).
    
    Returns:
        dict: Connection status for each database
    """
    connection_status = {
        "mysql": False,
        "postgres": False,
        "mongodb": False
    }
    
    # Test MySQL connection
    try:
        conn = pymysql.connect(
            host=os.getenv("MYSQL_HOST"),
            port=int(os.getenv("MYSQL_PORT", 3306)),
            user=os.getenv("MYSQL_USER"),
            password=os.getenv("MYSQL_PASSWORD"),
            database=os.getenv("MYSQL_DB"),
            ssl_disabled=True  # Disable SSL to avoid cryptography requirement
        )
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        connection_status["mysql"] = True
        print("✅ MySQL connection successful!")
    except Exception as e:
        print(f"❌ MySQL connection failed: {e}")
    
    # Test PostgreSQL connection
    try:
        conn = psycopg2.connect(
            host=os.getenv("POSTGRES_HOST"),
            port=int(os.getenv("POSTGRES_PORT", 5432)),
            user=os.getenv("POSTGRES_USER"),
            password=os.getenv("POSTGRES_PASSWORD"),
            dbname=os.getenv("POSTGRES_DB")
        )
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        connection_status["postgres"] = True
        print("✅ PostgreSQL connection successful!")
    except Exception as e:
        print(f"❌ PostgreSQL connection failed: {e}")
    
    # Test MongoDB connection
    try:
        # URL encode credentials
        user = quote_plus(os.getenv('MONGO_USER'))
        password = quote_plus(os.getenv('MONGO_PASSWORD'))
        
        mongo_uri = f"mongodb://{user}:{password}@{os.getenv('MONGO_HOST')}:{os.getenv('MONGO_PORT')}/{os.getenv('MONGO_DB')}?authSource={os.getenv('MONGO_AUTH_DB')}"
        client = MongoClient(mongo_uri)
        # Ping the server to test connection
        client.admin.command('ping')
        client.close()
        connection_status["mongodb"] = True
        print("✅ MongoDB connection successful!")
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
    
    return connection_status


def read_table_from_mysql(spark, table_or_query, is_query=False):
    """
    Read a table or execute a query from MySQL using Spark JDBC.
    
    Args:
        spark (SparkSession): Active Spark session
        table_or_query (str): Name of the table or SQL query to execute
        is_query (bool): Whether the input is a SQL query (True) or table name (False)
        
    Returns:
        DataFrame: Spark DataFrame containing table data
    """
    try:
        jdbc_url, connection_properties = get_mysql_jdbc_url()
        
        if is_query:
            # For SQL queries
            return spark.read.format("jdbc") \
                .option("url", jdbc_url) \
                .option("dbtable", f"({table_or_query}) AS query_result") \
                .option("user", connection_properties["user"]) \
                .option("password", connection_properties["password"]) \
                .option("driver", connection_properties["driver"]) \
                .option("useSSL", "false") \
                .load()
        else:
            # For direct table access
            return spark.read.format("jdbc") \
                .option("url", jdbc_url) \
                .option("dbtable", table_or_query) \
                .option("user", connection_properties["user"]) \
                .option("password", connection_properties["password"]) \
                .option("driver", connection_properties["driver"]) \
                .option("useSSL", "false") \
                .load()
    except Exception as e:
        print(f"Error reading from MySQL: {e}")
        raise


def read_table_from_postgres(spark, table_or_query, is_query=False):
    """
    Read a table or execute a query from PostgreSQL using Spark JDBC.
    
    Args:
        spark (SparkSession): Active Spark session
        table_or_query (str): Name of the table or SQL query to execute
        is_query (bool): Whether the input is a SQL query (True) or table name (False)
        
    Returns:
        DataFrame: Spark DataFrame containing table data
    """
    try:
        jdbc_url, connection_properties = get_postgres_jdbc_url()
        
        if is_query:
            # For SQL queries
            return spark.read.format("jdbc") \
                .option("url", jdbc_url) \
                .option("dbtable", f"({table_or_query}) AS query_result") \
                .option("user", connection_properties["user"]) \
                .option("password", connection_properties["password"]) \
                .option("driver", connection_properties["driver"]) \
                .load()
        else:
            # For direct table access
            return spark.read.format("jdbc") \
                .option("url", jdbc_url) \
                .option("dbtable", table_or_query) \
                .option("user", connection_properties["user"]) \
                .option("password", connection_properties["password"]) \
                .option("driver", connection_properties["driver"]) \
                .load()
    except Exception as e:
        print(f"Error reading from PostgreSQL: {e}")
        raise


def read_collection_from_mongodb(spark, collection_name, query=None):
    """
    Read a collection from MongoDB using PyMongo.
    
    Args:
        spark (SparkSession): Active Spark session
        collection_name (str): Name of the collection to read
        query (dict, optional): MongoDB query to filter documents
        
    Returns:
        DataFrame: Spark DataFrame containing collection data
    """
    try:
        # URL encode credentials
        user = quote_plus(os.getenv('MONGO_USER'))
        password = quote_plus(os.getenv('MONGO_PASSWORD'))
        
        # Use pymongo directly instead of the Spark MongoDB connector
        mongo_uri = f"mongodb://{user}:{password}@{os.getenv('MONGO_HOST')}:{os.getenv('MONGO_PORT')}/{os.getenv('MONGO_DB')}?authSource={os.getenv('MONGO_AUTH_DB')}"
        client = MongoClient(mongo_uri)
        db = client[os.getenv('MONGO_DB')]
        collection = db[collection_name]
        
        # Convert MongoDB documents to a list of dictionaries
        if query:
            documents = list(collection.find(query))
        else:
            documents = list(collection.find())
        
        # Convert ObjectId to string for better compatibility
        for doc in documents:
            if '_id' in doc:
                doc['_id'] = str(doc['_id'])
            
            # Convert datetime objects to strings
            for key, value in doc.items():
                if isinstance(value, dict):
                    for k, v in value.items():
                        if hasattr(v, 'isoformat'):
                            value[k] = v.isoformat()
                elif hasattr(value, 'isoformat'):
                    doc[key] = value.isoformat()
        
        # Create a Spark DataFrame from the documents
        if documents:
            df = spark.createDataFrame(documents)
        else:
            # If no documents, create an empty DataFrame
            df = spark.createDataFrame([], schema=None)
        
        client.close()
        return df
    except Exception as e:
        print(f"Error reading from MongoDB: {e}")
        raise


def write_dataframe_to_mysql(df, table_name, mode="overwrite"):
    """
    Write a Spark DataFrame to a MySQL table.
    
    Args:
        df (DataFrame): Spark DataFrame to write
        table_name (str): Name of the target table
        mode (str): Write mode (overwrite, append, etc.)
    """
    try:
        jdbc_url, connection_properties = get_mysql_jdbc_url()
        
        # Use option-based API
        df.write.format("jdbc") \
            .option("url", jdbc_url) \
            .option("dbtable", table_name) \
            .option("user", connection_properties["user"]) \
            .option("password", connection_properties["password"]) \
            .option("driver", connection_properties["driver"]) \
            .option("useSSL", "false") \
            .mode(mode) \
            .save()
    except Exception as e:
        print(f"Error writing to MySQL: {e}")
        raise


def write_dataframe_to_postgres(df, table_name, mode="overwrite"):
    """
    Write a Spark DataFrame to a PostgreSQL table.
    
    Args:
        df (DataFrame): Spark DataFrame to write
        table_name (str): Name of the target table
        mode (str): Write mode (overwrite, append, etc.)
    """
    try:
        jdbc_url, connection_properties = get_postgres_jdbc_url()
        
        # Use option-based API
        df.write.format("jdbc") \
            .option("url", jdbc_url) \
            .option("dbtable", table_name) \
            .option("user", connection_properties["user"]) \
            .option("password", connection_properties["password"]) \
            .option("driver", connection_properties["driver"]) \
            .mode(mode) \
            .save()
    except Exception as e:
        print(f"Error writing to PostgreSQL: {e}")
        raise


def write_dataframe_to_mongodb(df, collection_name):
    """
    Write a Spark DataFrame to a MongoDB collection using PyMongo.
    
    Args:
        df (DataFrame): Spark DataFrame to write
        collection_name (str): Name of the target collection
    """
    try:
        # Convert Spark DataFrame to pandas DataFrame and then to records
        pandas_df = df.toPandas()
        
        # Handle datetime columns by converting to strings
        for col in pandas_df.columns:
            if pandas_df[col].dtype.name.startswith('datetime'):
                pandas_df[col] = pandas_df[col].astype(str)
        
        records = pandas_df.to_dict('records')
        
        # URL encode credentials
        user = quote_plus(os.getenv('MONGO_USER'))
        password = quote_plus(os.getenv('MONGO_PASSWORD'))
        
        # Connect to MongoDB
        mongo_uri = f"mongodb://{user}:{password}@{os.getenv('MONGO_HOST')}:{os.getenv('MONGO_PORT')}/{os.getenv('MONGO_DB')}?authSource={os.getenv('MONGO_AUTH_DB')}"
        client = MongoClient(mongo_uri)
        db = client[os.getenv('MONGO_DB')]
        collection = db[collection_name]
        
        # Drop existing collection if overwriting
        collection.drop()
        
        # Insert records
        if records:
            collection.insert_many(records)
        
        client.close()
    except Exception as e:
        print(f"Error writing to MongoDB: {e}")
        raise