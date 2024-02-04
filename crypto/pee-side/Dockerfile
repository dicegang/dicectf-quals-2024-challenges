FROM pwn.red/jail
COPY --from=sagemath/sagemath / /srv
COPY --chmod=755 run.sh /srv/app/run
COPY flag.txt server.py /srv/app/
ENV JAIL_TIME=5400 JAIL_PIDS=20 JAIL_MEM=300M JAIL_CPU=1000 JAIL_TMP_SIZE=1M JAIL_CONNS=10 JAIL_ENV_HOME=/tmp