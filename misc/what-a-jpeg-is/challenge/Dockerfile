FROM python:3.10.13-slim-bookworm

WORKDIR /tmp

RUN pip install pillow numpy transformers datasets --no-cache
RUN pip install torch torchvision --no-cache --index-url https://download.pytorch.org/whl/cpu
COPY download.py .
RUN python3 download.py

FROM pwn.red/jail
COPY --from=0 / /srv
COPY flag.txt challenge.py /srv/app/
RUN cp -r /srv/tmp/cache /srv/app/cache

COPY run.sh /srv/app/run
RUN chmod +x /srv/app/run

# /dev/shm fix for rpjail
RUN mkdir /srv/tmp/shm
RUN ln -s /srv/tmp/shm /srv/dev/shm

ENV JAIL_TIME=180 JAIL_PIDS=20 JAIL_MEM=1200M JAIL_CPU=750 JAIL_TMP_SIZE=512M
ENV JAIL_ENV_HF_HOME=/tmp/cache/huggingface