FROM python:3.10

WORKDIR /usr/src/nsec3map
COPY . /usr/src/nsec3map

RUN apt-get -y update
RUN apt-get install -y libssl-dev
# libssl3 is not yet available, so for now we'll have to do without the extension module...
#RUN apt-get install -y libssl3 libssl-dev

RUN pip install dnspython
RUN pip install numpy
RUN pip install scipy

RUN pip install .[predict]

WORKDIR /host
ENTRYPOINT ["n3map"]
