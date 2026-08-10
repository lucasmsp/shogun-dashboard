import os
import sys
import time
import signal
import psutil
from project.storage import DatasetManager
from project.auxiliar import logging

SPARK_PORT = os.environ.get("SPARK_UI_PORT", "4040")
SPARK_VCORES = os.environ.get("SPARK_VCORES", "8")
SPARK_MEMORY = os.environ.get("SPARK_MEMORY", "10g")
DELTA_VERSION = os.environ.get("DELTA_VERSION", "3.3.0")

SHODAN_FOLDER = os.environ.get("SHODAN_FOLDER", "/opt/input_data/")
RESULT_FOLDER = os.environ.get("RESULT_FOLDER", "/opt/output_data/")

output_filepath = RESULT_FOLDER + "/tlhop-epss-dashboard"

def run_dummy(timestamp):
    with open("/tmp/run-dummy", "w") as f:
        f.write(str(timestamp))


active_spark_session = None


def start_processing(dm, day_fmt1):
    """
    Start the processing of the data.

    Args:
        dm (DatasetManager): Data manager.
        day_fmt1 (str): Day in format yyyy-mm-dd.
    
    Returns:
        None
    """
    
    def handle_signal(signum, frame):
        logging.info(f"Subprocess received signal {signum}. Cleaning up Spark Session and JVM...")
        global active_spark_session
        if active_spark_session is not None:
            try:
                active_spark_session.stop()
            except Exception as e:
                logging.error(f"Error stopping Spark Session: {e}")
            active_spark_session = None
        kill_spark_java()
        sys.exit(1)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    try:
        logging.info(f"Starting pyspark computation - day_fmt1: {day_fmt1}...")

        run(day_str=day_fmt1)
        dm.remove_old_data()
        dm.check_available_datasets()

        logging.info("Finished")
    except Exception as e:
        logging.error(e)
        sys.exit(1)
    sys.exit(0)
    

def run(day_str, first_execution=False):
    """
    Run the computation.

    Args:
        day_str (str): Day in format yyyy-mm-dd.
        first_execution (bool): Whether it is the first execution.
    
    Returns:
        None
    """

    global active_spark_session
    from pyspark.sql import SparkSession
    from tlhop.algorithms import ShodanVulnerabilitiesBanners
    from tlhop.crawlers import NISTNVD
    t1 = time.time()
    spark = SparkSession.builder\
                .master(f"local[{SPARK_VCORES}]")\
                .config("spark.driver.memory", SPARK_MEMORY)\
                .config("spark.ui.port", SPARK_PORT)\
                .config("spark.driver.extraClassPath", f"/opt/spark/jars/delta-spark_2.12-{DELTA_VERSION}.jar:/opt/spark/jars/delta-storage-{DELTA_VERSION}.jar")\
                .config("spark.submit.pyFiles", f"/opt/spark/jars/delta-spark_2.12-{DELTA_VERSION}.jar")\
                .config("spark.sql.extensions", " io.delta.sql.DeltaSparkSessionExtension")\
                .config("spark.sql.catalog.spark_catalog", "org.apache.spark.sql.delta.catalog.DeltaCatalog")\
                .getOrCreate()
    active_spark_session = spark
    try:
        if first_execution:
            crawler = NISTNVD()
            crawler.download()

        day_shodan_format = day_str.replace("-", "")
        input_filepath = SHODAN_FOLDER + f"/BR.{day_shodan_format}.json.bz2"

        algorithm = ShodanVulnerabilitiesBanners(input_filepath, output_filepath, epss_day=day_str,
                                                 org_refinement=True, fix_brazilian_cities=True)
        algorithm.compute_general_report()
        algorithm.gen_query_summary()
        algorithm.gen_query_orgs()
        algorithm.gen_query_ips()
        algorithm.gen_query_vulns()
        algorithm.gen_query_as()
        algorithm.gen_query_ports()
    finally:
        if active_spark_session is not None:
            try:
                active_spark_session.stop()
            except Exception as e:
                logging.error(f"Error stopping Spark Session in finally block: {e}")
            active_spark_session = None
        kill_spark_java()

    t2 = time.time()
    logging.info("Process completed in {0:.1f}s".format(t2-t1))
    
    return 'Ok' 

def kill_spark_java():
    """Making sure that pyspark java process is killed"""
    try:
        parent = psutil.Process()
        children = parent.children(recursive=False)

        for child in children:
            if child.name() == "java":
                try:
                    os.kill(child.pid, signal.SIGTERM)
                    logging.info(f"Spark java process (PID {child.pid}) is killed.")
                except Exception as e:
                    logging.warning(f"Failed to kill spark java process (PID {child.pid}): {e}")
    except Exception as e:
        logging.error(f"Error during kill_spark_java: {e}")


