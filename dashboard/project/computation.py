import os
import time
from project.storage import DatasetManager

SPARK_PORT = os.environ.get("SPARK_UI_PORT", "4040")
SPARK_VCORES = os.environ.get("SPARK_VCORES", "8")
SPARK_MEMORY = os.environ.get("SPARK_MEMORY", "10g")
DELTA_VERSION = os.environ.get("DELTA_VERSION", "3.0.0")

SHODAN_FOLDER = os.environ.get("SHODAN_FOLDER", "/opt/input_data/")
RESULT_FOLDER = os.environ.get("RESULT_FOLDER", "/opt/output_data/")

output_filepath = RESULT_FOLDER + "/tlhop-epss-dashboard"

def run_dummy(timestamp):
    with open("/tmp/run-dummy", "w") as f:
        f.write(str(timestamp))


def start_processing(dm, day_fmt1):
    
    try:
        print(f"[INFO][start_processing] - Starting computation - day_fmt1: {day_fmt1}...", flush=True)

        run(day_str=day_fmt1)
        dm.remove_old_data()
        dm.check_available_datasets()

        print("[INFO][start_processing] - Finished", flush=True)
    except:
        return False
    return True
    

def run(day_str, first_execution=False):
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

    if first_execution:
        crawler = NISTNVD()
        crawler.download()

    day_shodan_format = day_str.replace("-", "")
    input_filepath = SHODAN_FOLDER + f"/BR.{day_shodan_format}.json.bz2"

    algorithm = ShodanVulnerabilitiesBanners(input_filepath, output_filepath, epss_day=day_str,
                                             org_refinement=True, fix_brazilian_cities=True)
    algorithm.compute_general_report()
    algorithm.gen_extra_query1()
    algorithm.gen_extra_query2()
    algorithm.gen_extra_query3()
    algorithm.gen_extra_query4()

    spark.stop()
    t2 = time.time()
    print("[Computation] Process completed in {0:.1f}s".format(t2-t1), flush=True)
