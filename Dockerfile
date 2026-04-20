FROM ubuntu:latest

RUN apt-get update

RUN apt-get install -y ca-certificates

RUN apt-get -y upgrade

COPY target/release/office_audit_log_collector /OfficeAuditLogCollector

WORKDIR /app

RUN chmod +x /OfficeAuditLogCollector && \
    chown -R 1001:1001 /app /OfficeAuditLogCollector

USER 1001

ENTRYPOINT ["/OfficeAuditLogCollector"]
