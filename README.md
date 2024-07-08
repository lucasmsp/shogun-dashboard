# TLHOP Dashboard

This project aims to provide a dashboard with various panels for analyzing cybersecurity vulnerabilities using data from the Shodan search engine. Currently, there are 5 panels available, which differ in levels of abstraction and usability:


1. Summary of the number of vulnerabilities, CVE scores, and risk prioritization scores (EPSS);
2. Analysis of vulnerabilities related to IPs or organizations;
3. List of CVEs found in the daily dump, along with the number of vulnerable IPs and organizations;
4. Interface for banner-level evaluation. Provides detailed information and visualizations about the banner collected by Shodan;
5. Collection of maps for statistical evaluations relating to the distribution of Brazilian states.


Its functionality is described as follows: Daily Shodan dumps in JSON format are monitored in the directory defined by the environment variable *SHODAN_FOLDER*. Periodically (as defined by the *CRON_EXPRESSION*), the system will check for the presence of a new dump and, when found, will initiate the processing of this dump in Spark to filter the banners collected by Shodan with vulnerabilities into a more efficient and enriched format. Once this result is saved, the panels described above will be available for queries in its web interface.


## How to install:

The project is available at DockerHub through the image `lucasmsp/dashboards`, but users can also built manually using the Dockerfile provided in the repository. The `docker-compose.yaml` file illustrates the necessary configurations to start the service. The main definitions are:

- **CRON_EXPRESSION**: A cron expression specifying how often the application will check for new Shodan data dumps. Example: "0 8 * * *" (each day at 8 AM)
- **SPARK_UI_PORT**: Port for the Spark UI (e.g., 4040), which can be exposed outside the container to help monitor and evaluate the performance of Spark processing;
- **SPARK_VCORES**: Number of VCPUs available for data processing via Spark;
- **SPARK_MEMORY**: Amount of RAM available for data processing via Spark (e.g., 6g);
- **SHODAN_FOLDER**: Directory where the Shodan dumps will be monitored.
- **RESULT_FOLDER**: Directory where the processing results will be saved.
- **TLHOP_DATASETS_PATH**: Directory where the TLHOP library will save its auxiliary files.

**NOTE**: When using containers, it is advisable to map volumes for *SHODAN_FOLDER*, *RESULT_FOLDER*, and *TLHOP_DATASETS_PATH* to ensure data persistence.



## Developer's Guide

Developing activities in Docker containers may not be very user-friendly, in this case, we recommend using only the PostgreSQL database as a container, running the dashboard locally during this development stage. To do this, developers can start the database using the command `docker compose up postgres`, then using the command `bash start-dev.sh` to start the dashboard server responsible to communicate with the PostgreSQL.