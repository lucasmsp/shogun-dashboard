FROM spark:3.5.5-java17-python3
LABEL maintainer="Lucas Miguel Ponce <lucasmsp@dcc.ufmg.br>"
USER 0
ENV DELTA_VERSION=3.3.0

# Installing Spark and Delta Lake
RUN pip install --default-timeout=1000 --user delta-spark==$DELTA_VERSION \
    && curl -Lo /opt/spark/jars/delta-spark_2.12-$DELTA_VERSION.jar https://repo1.maven.org/maven2/io/delta/delta-spark_2.12/$DELTA_VERSION/delta-spark_2.12-$DELTA_VERSION.jar \
    && curl -Lo /opt/spark/jars/delta-storage-$DELTA_VERSION.jar https://repo1.maven.org/maven2/io/delta/delta-storage/$DELTA_VERSION/delta-storage-$DELTA_VERSION.jar

# Configuring TLHOP Library
RUN apt-get update && apt install -y git \
    && cd /opt/ \
    && git clone --depth 1 https://github.com/lucasmsp/tlhop-library.git \
    && cd /opt/tlhop-library \
    && python3 setup.py sdist \
    && pip install --user dist/tlhop-library-$(python3 -c "exec(open('tlhop/__init__.py').read()); print(__version__)").tar.gz \
    && rm -rf /var/lib/apt/lists/*

# Configuring TLHOP Dashboard
COPY dashboard/requirements.txt /tmp/requirements.txt 
RUN pip install --default-timeout=1000 --user -r /tmp/requirements.txt --no-cache-dir


ENV DASHBOARD_APP=/opt/dashboard
COPY dashboard $DASHBOARD_APP 
WORKDIR $DASHBOARD_APP
ENTRYPOINT ["python3", "-u", "app.py"]
