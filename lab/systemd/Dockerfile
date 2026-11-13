# Víctima con systemd de verdad como PID 1: lo que el mini-lab no puede probar (el servicio, su
# endurecimiento, journald, logind). Solo parte de la imagen oficial y de los paquetes de Ubuntu.
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
       systemd systemd-sysv dbus python3 nftables ufw iptables netcat-openbsd procps \
       openssh-server rsyslog cron sudo tmux logrotate auditd \
    && rm -f /etc/systemd/system/multi-user.target.wants/{e2scrub_reap,systemd-resolved}.service \
    # auditd es dependencia de Arx; en un contenedor el núcleo no lo deja arrancar
    && systemctl mask auditd \
    && systemctl mask systemd-udevd systemd-modules-load systemd-firstboot \
       sys-kernel-debug.mount sys-kernel-tracing.mount getty@tty1.service console-getty.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
