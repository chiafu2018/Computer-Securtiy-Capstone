# Use an official base image
FROM ubuntu:24.04

# Install required tools, libraries, and OpenSSH Server
RUN apt update && \
    apt install -y \
        openssh-server build-essential python3 python3-pip vim-common unzip \
        zip imagemagick perl cmake autoconf libtool zlib1g-dev git libzstd-dev \
        zstd python3-paramiko xz-utils lzip zlib1g gzip \
    && rm -rf /var/lib/apt/lists/* 

WORKDIR /tmp

# Install openssl, liboqs and oqs-provider
RUN git clone https://github.com/openssl/openssl.git -b openssl-3.4.1 --depth=1 \
    && cd openssl \
    && ./Configure \
        no-ssl no-tls1 no-tls1_1 no-afalgeng \
        no-shared threads -lm \
    && make -j8 \
    && make install_sw install_ssldirs \
    && cd ..

RUN git clone https://github.com/open-quantum-safe/liboqs.git -b 0.12.0 --depth=1 \
    && cd liboqs \
    && cmake \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_USE_OPENSSL=OFF \
        -DCMAKE_BUILD_TYPE=Release \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_DIST_BUILD=ON \
        -B build \
        -S . \
    && make -Cbuild -j8 install \
    && cd ..

RUN git clone https://github.com/open-quantum-safe/oqs-provider.git -b 0.8.0 --depth=1 \
    && cd oqs-provider \
    && cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -B build \
        -S . \
    && make -Cbuild -j8 install \
    && cd ..

# Load OQS by default
RUN sed -i 's/default = default_sect/default = default_sect\noqsprovider = oqsprovider_sect\n/g' /usr/local/ssl/openssl.cnf \
    && sed -i 's/# activate = 1/activate = 1\n\n[oqsprovider_sect]\nactivate = 1/g' /usr/local/ssl/openssl.cnf

RUN rm -rf openssl liboqs oqs-provider

# Add user for SSH access (change 'csc2025' to your desired password)
RUN useradd -ms /bin/bash csc2025
RUN echo 'csc2025:csc2025' | chpasswd
RUN echo 'csc2025 ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Create SSH directory
RUN mkdir /var/run/sshd

# Open port 22 for SSH access
EXPOSE 22

# Copy the entire project directory
COPY . /app

# Set the working directory
WORKDIR /app

# Set Permission to 777
RUN chmod -R 777 /app
