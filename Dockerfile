FROM python:3.7


RUN apt-get update && \
	apt-get install -y git nmap 

RUN git clone https://github.com/CrimsonK1ng/Reconnoitre.git recon

WORKDIR /recon

RUN pip install requirements && python setup.py install

ENTRYPOINT ["reconnoiter"]

