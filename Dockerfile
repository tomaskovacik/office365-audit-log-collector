FROM alpine:latest

COPY target/release/office_audit_log_collector /office_audit_log_collector

RUN apk add --no-cache ca-certificates libgcc

WORKDIR /app

RUN chmod +x /office_audit_log_collector && \
    chown -R 1001:1001 /app /office_audit_log_collector

USER 1001

ENTRYPOINT ["/office_audit_log_collector"]
