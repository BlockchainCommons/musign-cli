FROM rust:slim as bc-base
RUN apt update -y
RUN apt install -y dpkg-dev build-essential 

FROM bc-base
WORKDIR /app
COPY . source
COPY .git source/.git
WORKDIR source
RUN cargo install cargo-deb
RUN cargo deb