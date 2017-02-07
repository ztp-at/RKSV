FROM ubuntu:16.04
MAINTAINER ZTP.at

# Runtime deps
RUN apt-get update && \
	apt-get install -y python-virtualenv mesa-common-dev \
	libgl1-mesa-dev libssl-dev libpython2.7-dev libzbar-dev \
	build-essential gettext libffi-dev

# APK build deps
RUN dpkg --add-architecture i386 && apt-get update && \
	apt-get install -y default-jdk git unzip wget libncurses5:i386 \
	libstdc++6:i386 zlib1g:i386 autoconf

# for GUI
RUN apt-get install -y openssh-server
EXPOSE 22

# user setup
RUN useradd -m rksv && echo 'rksv:rksv' | chpasswd && \
	chsh rksv -s /bin/bash
RUN apt-get install -y sudo && echo 'rksv ALL=(root) NOPASSWD: ALL' > \
	/etc/sudoers.d/rksv && chmod 440 /etc/sudoers.d/rksv

# setup repo
COPY . /home/rksv/pyreg
RUN chown -R rksv:rksv /home/rksv/pyreg && \
	chmod -R u+rwX,go+rX /home/rksv/pyreg

# some preparation
RUN cd /home/rksv/pyreg && su -c 'make env' rksv
RUN cd /home/rksv/pyreg && \
	su -c 'source .pyenv/bin/activate && make compile-trans' rksv
RUN echo 'source ~/pyreg/.pyenv/bin/activate' >> /home/rksv/.profile

USER rksv
WORKDIR /home/rksv/pyreg
ENTRYPOINT /bin/bash -l
