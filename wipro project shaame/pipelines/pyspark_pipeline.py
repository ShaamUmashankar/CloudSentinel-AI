"""
CloudSentinel AI - AWS Glue / PySpark ETL Pipeline Specification & Implementation
This script defines the scalable PySpark ETL job designed for AWS Glue or Amazon EMR.
It processes terabyte-scale CloudTrail event archives in Amazon S3, normalizes events,
performs feature engineering, partitions data, and sinks to Amazon Redshift / S3 Parquet.
"""

import sys
import os
from typing import Dict, Any

# Glue / Spark Job Blueprint
GLUE_JOB_DEFINITION = """
# AWS Glue PySpark Job Configuration:
# - Worker Type: G.1X (4 vCPU, 16 GB memory)
# - Number of Workers: 10 (Scalable to 100)
# - Glue Version: 4.0 (Spark 3.3, Python 3.10)
# - Source: s3://cloudsentinel-cloudtrail-logs-raw/year=YYYY/month=MM/
# - Target (Parquet): s3://cloudsentinel-analytics-lake/normalized_events/
# - Target (Redshift): jdbc:redshift://cloudsentinel-dw.c123.us-east-1.redshift.amazonaws.com:5439/security_dw
"""

def get_glue_etl_script_source() -> str:
    """Returns the production AWS Glue PySpark script text for deployment or review."""
    return '''
import sys
from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from pyspark.sql import functions as F
from pyspark.sql.types import *
from pyspark.sql.window import Window

args = getResolvedOptions(sys.argv, ['JOB_NAME', 'INPUT_S3_PATH', 'OUTPUT_S3_PATH', 'REDSHIFT_JDBC_URL', 'TEMP_DIR'])

sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
job = Job(glueContext)
job.init(args['JOB_NAME'], args)

# 1. Define Explicit CloudTrail Schema
cloudtrail_schema = StructType([
    StructField("eventVersion", StringType(), True),
    StructField("userIdentity", StructType([
        StructField("type", StringType(), True),
        StructField("principalId", StringType(), True),
        StructField("arn", StringType(), True),
        StructField("accountId", StringType(), True),
        StructField("userName", StringType(), True)
    ]), True),
    StructField("eventTime", StringType(), True),
    StructField("eventSource", StringType(), True),
    StructField("eventName", StringType(), True),
    StructField("awsRegion", StringType(), True),
    StructField("sourceIPAddress", StringType(), True),
    StructField("userAgent", StringType(), True),
    StructField("errorCode", StringType(), True),
    StructField("errorMessage", StringType(), True),
    StructField("eventID", StringType(), True),
    StructField("eventType", StringType(), True)
])

# 2. Read CloudTrail JSON from S3 Data Lake
raw_df = spark.read.schema(cloudtrail_schema).json(args['INPUT_S3_PATH'])

# 3. Deduplication on eventID
dedup_df = raw_df.dropDuplicates(["eventID"])

# 4. Feature Engineering & Transformations
transformed_df = dedup_df \\
    .withColumn("timestamp", F.to_timestamp("eventTime", "yyyy-MM-dd'T'HH:mm:ss'Z'")) \\
    .withColumn("principal_id", F.coalesce(F.col("userIdentity.userName"), F.col("userIdentity.principalId"), F.lit("Unknown"))) \\
    .withColumn("is_internal_ip", F.when(
        F.col("sourceIPAddress").rlike("^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|127\\.0\\.0\\.1)"), 1
    ).otherwise(0)) \\
    .withColumn("is_error", F.when(F.col("errorCode").isNotNull(), 1).otherwise(0)) \\
    .withColumn("is_privilege_related", F.when(
        F.col("eventName").isin(
            "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
            "CreateAccessKey", "CreateLoginProfile", "AssumeRole"
        ), 1
    ).otherwise(0)) \\
    .withColumn("is_tampering", F.when(
        F.col("eventName").isin("StopLogging", "DeleteTrail", "UpdateTrail", "DeleteFlowLogs"), 1
    ).otherwise(0)) \\
    .withColumn("is_auth_failure", F.when(
        (F.col("eventName") == "ConsoleLogin") & (F.col("is_error") == 1), 1
    ).otherwise(0))

# 5. Window Functions: Calculate Principal Event Frequency over 15-Minute Windows
window_spec = Window.partitionBy("principal_id").orderBy(F.col("timestamp").cast("long")).rangeBetween(-900, 0)
transformed_df = transformed_df.withColumn("event_frequency_15m", F.count("eventID").over(window_spec))

# 6. Partition by Date and Write to S3 Analytics Layer in Parquet Format
transformed_df \\
    .withColumn("year", F.year("timestamp")) \\
    .withColumn("month", F.month("timestamp")) \\
    .withColumn("day", F.dayofmonth("timestamp")) \\
    .write \\
    .partitionBy("year", "month", "day") \\
    .mode("append") \\
    .parquet(args['OUTPUT_S3_PATH'])

# 7. Optional Sink to Amazon Redshift DW
# transformed_df.write \\
#     .format("io.github.spark_redshift") \\
#     .option("url", args['REDSHIFT_JDBC_URL']) \\
#     .option("dbtable", "public.normalized_cloudtrail_events") \\
#     .option("tempdir", args['TEMP_DIR']) \\
#     .mode("append") \\
#     .save()

job.commit()
'''

class PySparkPipelineManager:
    """
    Manages and inspects PySpark ETL pipeline definitions.
    Enables local execution if PySpark environment is available,
    otherwise provides architecture specification, validation, and schema definitions.
    """

    @classmethod
    def get_pipeline_status(cls) -> Dict[str, Any]:
        pyspark_available = False
        try:
            import pyspark # noqa: F401
            pyspark_available = True
        except ImportError:
            pyspark_available = False

        return {
            "pyspark_installed": pyspark_available,
            "engine": "PySpark 3.3+ (AWS Glue 4.0 Architecture)" if pyspark_available else "Local Pandas Engine Active (PySpark Module Available for Cloud Deployment)",
            "glue_job_name": "CloudSentinel-CloudTrail-ETL-Job",
            "supported_sources": ["s3://cloudsentinel-raw-logs/", "local_json_stream"],
            "supported_sinks": ["Amazon S3 (Parquet Partitioned)", "Amazon Redshift Data Warehouse"],
            "features_extracted": [
                "event_frequency_15m",
                "is_internal_ip",
                "is_privilege_related",
                "is_tampering",
                "is_auth_failure",
                "windowed_principal_activity"
            ],
            "glue_config_blueprint": GLUE_JOB_DEFINITION.strip()
        }
