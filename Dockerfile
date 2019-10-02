FROM python:3.7


RUN apt update && \
	apt install git nmap 


RUN https://github.com/CrimsonK1ng/Reconnoitre.git recon

WORKDIR /recon

RUN pip install requirements && python setup.py install



