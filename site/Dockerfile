# SuckerPot public site: static files served by unprivileged nginx on port 8080.
FROM nginxinc/nginx-unprivileged:1.29.3-alpine3.22

# The image already runs as the non-root "nginx" user (uid 101).
COPY --chown=root:root --chmod=0644 nginx.conf /etc/nginx/conf.d/default.conf
COPY --chown=root:root public/ /usr/share/nginx/html/

USER root
RUN find /usr/share/nginx/html -type d -exec chmod 0755 {} + \
 && find /usr/share/nginx/html -type f -exec chmod 0644 {} +
USER 101

ENV NGINX_ENTRYPOINT_QUIET_LOGS=1
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
