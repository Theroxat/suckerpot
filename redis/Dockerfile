# Small image so that the entrypoint and config are baked in and the container
# can run with a read-only root filesystem, as a non-root user, with no bind mounts.
FROM redis:8.0.6-alpine3.21

COPY redis.conf /etc/redis/redis.conf
COPY entrypoint.sh /usr/local/bin/suckerpot-redis-entrypoint
# Files are copied as root and must stay world-readable and not writable.
RUN chmod 0444 /etc/redis/redis.conf && chmod 0555 /usr/local/bin/suckerpot-redis-entrypoint

# 999 is the uid/gid of the "redis" user of the official image; /data is already owned by it.
USER 999:999

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD ["sh", "-c", "REDISCLI_AUTH=\"$REDIS_HEALTH_PASSWORD\" redis-cli --user health ping | grep -q PONG"]

ENTRYPOINT ["/usr/local/bin/suckerpot-redis-entrypoint"]
CMD ["redis-server", "/etc/redis/redis.conf"]
