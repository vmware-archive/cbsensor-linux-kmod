# NOTE: This Makefile is for use only within the Carbon Black network

IMAGE=artifactory-pub.bit9.local:5002/cbr/cbr-linux-builder-kernel
USER_ID=`id -u`
GROUP_ID=`id -g`

SHELL=/bin/bash

CONTAINER_ID=$(shell docker ps -q -f name=cbsensor-builder)
KERNEL_PACKAGE=kernel-devel/3.10.0-1127.el7.x86_64@cb/stable

.PHONY: all container build clean

all: build

container:
	@test -z $(CONTAINER_ID) \
	&& docker pull ${IMAGE} \
	&& docker run -it -d --rm \
			-v$(PWD):/home/conan/project \
			-e USER_ID=${USER_ID} \
			-e GROUP_ID=${GROUP_ID} \
			--name cbsensor-builder \
			${IMAGE} bash && sleep 1 || true
#	sleep 1 # Pause while the container starts up.

build: container
	docker exec -it -u conan cbsensor-builder bash -c "\
		mkdir -p project/build \
		&& cd project/build \
		&& rm -f conanfile.txt \
		&& sed '/build_requires/a $(KERNEL_PACKAGE)' ../conanfile.txt > conanfile.txt \
		&& conan install . -j kernel-headers.json \
		&& cmake -DKERNELDIR=`jq -r .installed[0].packages[0].cpp_info.rootpath < kernel-headers.json`/kernel .. \
		&& make VERBOSE=1 \
		"

clean:
	rm -rf build
	@docker stop cbsensor-builder 2>/dev/null || true
