FROM debian:bookworm

WORKDIR /usr/src/nsec3map
COPY . /usr/src/nsec3map

RUN apt-get -y update
RUN apt-get install -y libssl3 libssl-dev \
	python3 \
	python3-dev \
	python3-pip \
	python3-dnspython \
	python3-numpy \
	python3-scipy

RUN pip install .[predict]

WORKDIR /host
ENTRYPOINT ["n3map"]
