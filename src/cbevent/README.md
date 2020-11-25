# cbevent

Defines the event structure which is the common interface for communications between event collectors (CBR/TH kernel module, eBPF, file sources) and the CBR and TH daemon processes.

## Building
run: `python build.py`

## Build within a docker container

Make sure you have the latest docker image:
```
docker pull artifactory-pub.bit9.local:5000/cbr/cbr-linux-builder
```
Launch the docker container:
```
docker run -it -e USER_ID=`id -u` -e GROUP_ID=`id -g` --rm -v $PWD:/home/conan/src artifactory-pub.bit9.local:5000/cbr/cbr-linux-builder bash
```

From within the docker container:
```
cd src
python build.py
```
