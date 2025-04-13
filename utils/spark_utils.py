from pyspark.sql import SparkSession
import os
from dotenv import load_dotenv

def create_spark_session():
    """
    Create and configure a Spark session based on environment variables.
    
    Returns:
        SparkSession: Configured Spark session
    """
    load_dotenv()
    
    # Set Java home for PySpark from environment variables
    java_home = os.getenv("JAVA_HOME")
    if java_home:
        os.environ["JAVA_HOME"] = java_home
    
    # Get Spark configuration from environment variables
    spark_master = os.getenv("SPARK_MASTER", "local[*]")
    app_name = os.getenv("SPARK_APP_NAME", "CyberSecurityETL")
    log_level = os.getenv("SPARK_LOG_LEVEL", "ERROR")
    
    # Create Spark session with necessary configurations and JDBC drivers
    # Note: We're removing the MongoDB connector as we'll use PyMongo directly
    spark = (SparkSession.builder
             .config("spark.driver.host", "localhost")
             .master(spark_master)
             .appName(app_name)
             .config("spark.jars.packages", 
                     "org.postgresql:postgresql:42.6.0,"
                     "com.mysql:mysql-connector-j:8.0.33")
             .config("spark.driver.extraJavaOptions", "-Dlog4j.logLevel=info")
             .getOrCreate())
    
    # Set log level
    spark.sparkContext.setLogLevel(log_level)
    
    return spark


def stop_spark_session(spark):
    """
    Properly stop the Spark session
    
    Args:
        spark (SparkSession): Active Spark session to stop
    """
    if spark is not None:
        spark.stop()