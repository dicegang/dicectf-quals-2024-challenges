# syntax=docker/dockerfile:1.6.0
FROM python:3.11.7-slim-bookworm
RUN pip --no-cache-dir install pyhelayers numpy

FROM pwn.red/jail
COPY --from=0 / /srv
ADD --chmod=644 https://static.dicega.ng/uploads/14438b31d64c192a29452a151034a336a5e7d3023d57ba8ba9d9039f17419bc6/public.key /srv/app/
COPY --link private.key x.ctxt flag.txt /srv/app/
COPY --link server.py /srv/app/run
ENV JAIL_MEM=4G JAIL_CPU=1000 JAIL_PIDS=30 JAIL_TIME=60 JAIL_CONNS=4 JAIL_TMP_SIZE=1M
