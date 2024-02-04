FROM rust:slim as build

WORKDIR /app
COPY ./dicenet .
RUN cargo build --release --bin server

FROM pwn.red/jail
COPY --from=build / /srv
RUN cp /srv/app/target/release/server /srv/app
COPY ./dicenet/net/model.json ./dicenet/net/weights.json /srv/app/
COPY ./run.sh /srv/app/run
ENV JAIL_TIME=60 JAIL_MEM=200M JAIL_CPU=1000
