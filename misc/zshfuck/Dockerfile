FROM ubuntu AS app
RUN apt-get update && apt-get install -y zsh && rm -rf /var/lib/apt/lists/*

FROM pwn.red/jail
COPY --from=app / /srv

RUN mkdir -p /srv/app/y0u/w1ll/n3v3r_g3t/th1s/
COPY getflag /srv/app/y0u/w1ll/n3v3r_g3t/th1s/
RUN chmod 111 /srv/app/y0u/w1ll/n3v3r_g3t/th1s/getflag
COPY jail.zsh /srv/app/run
RUN chmod +x /srv/app/run
ENV JAIL_MEM=20M
