FROM python:2.7

WORKDIR /usr/src/nsec3map
COPY . /usr/src/nsec3map

RUN apt-get -y update
RUN apt-get install -y libssl-dev

RUN pip install dnspython
RUN pip install numpy
RUN pip install scipy

RUN python setup.py install

WORKDIR /host
ENTRYPOINT ["n3map"]