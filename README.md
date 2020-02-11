# Steps to run Configurator-exporter

## Clone deepInsights git repo
git clone https://github.com/maplelabs/configurator-exporter.git /opt/configurator-exporter

###### Note: replace USERNAME

## Set Pythonpath

export PYTHONPATH=$PYTHONPATH:/opt/configurator-exporter

## Run configurator server

cd /opt/configurator-exporter

python api_server.py -h
usage: api_server.py [-h] [-p PORT] [-i HOST]

optional arguments:

  -h, --help            show this help message and exit

  -p PORT, --port PORT  port on which configurator will listen, Default 8585

  -i HOST, --ip HOST    host ip on which configurator will listen, Default 0.0.0.0


python api_server.py -i 0.0.0.0 -p 8585




