from pyspark.sql import SparkSession
# from tlhop.algorithms import ShodanVulnerabilitiesBanners
import os
import time

SPARK_PORT = os.environ.get("SPARK_UI_PORT", "4040")
SPARK_VCORES = os.environ.get("SPARK_VCORES", "8")
SPARK_MEMORY = os.environ.get("SPARK_MEMORY", "10g")
# SHODAN_FOLDER = os.environ["SHODAN_FOLDER"]

output_filepath = "./data/tlhop-epss-dashboard.delta"
output_filepath_view1 = "./data/tlhop-epss-dashboard-view1.delta"
output_filepath_view2a = "./data/tlhop-epss-dashboard-view2a.delta"
output_filepath_view2b = "./data/tlhop-epss-dashboard-view2b.delta"
output_filepath_view3 = "./data/tlhop-epss-dashboard-view3.delta"

def run_dummy(timestamp):
    with open("./data/tmp", "w") as f:
        f.write(str(timestamp))


def run(day_str):

    t1 = time.time()
    spark = SparkSession.builder\
                .master(f"local[{SPARK_MEMORY}]")\
                .config("spark.driver.memory", SPARK_MEMORY)\
                .config("spark.ui.port", SPARK_PORT)\
                .getOrCreate()

    day_shodan_format = day_str.replace("-", "")
    input_filepath = SHODAN_FOLDER + "/BR.{day_shodan_format}.json.bz2"
    
    algorithm = ShodanVulnerabilitiesBanners(org_refinement=True, fix_brazilian_cities=True)
    algorithm.compute_general_report(input_filepath, output_filepath, check_nvd=True, epss_day=day_str)

    v1 = algorithm.gen_extra_query1()
    v1.write.format("delta").mode("append").option("mergeSchema", "true").save(output_filepath_view1)

    v2a = algorithm.gen_extra_query2a()
    v2a.write.format("delta").mode("append").option("mergeSchema", "true").save(output_filepath_view2a)

    v2b = algorithm.gen_extra_query2b()
    v2b.write.format("delta").mode("append").option("mergeSchema", "true").save(output_filepath_view2b)

    v3 = algorithm.gen_extra_query3()
    v3.write.format("delta").mode("append").option("mergeSchema", "true").save(output_filepath_view3)

    spark.stop()
    t2 = time.time()
    print("Process completed in {0:.1f}s".format(t2-t1))