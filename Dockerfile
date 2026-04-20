FROM alpine:3.21

RUN apk add --no-cache ca-certificates libgcc

COPY office_audit_log_collector /office_audit_log_collector

WORKDIR /app

RUN chmod +x /office_audit_log_collector && \
    chown -R 1001:1001 /app /office_audit_log_collector

USER 1001

ENTRYPOINT ["/office_audit_log_collector"]
