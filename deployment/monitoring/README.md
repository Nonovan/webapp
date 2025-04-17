# Monitoring Configuration for Cloud Infrastructure Platform

This directory contains monitoring configuration files for the Cloud Infrastructure Platform, providing comprehensive observability through metrics, logs, and alerts.

## Directory Structure

monitoring/
├── prometheus/             # Prometheus monitoring configuration
│   ├── prometheus.yml      # Main Prometheus configuration
│   └── alert-rules.yml     # Alert definitions
├── grafana/                # Grafana dashboards and configuration
│   ├── dashboards/         # Dashboard JSON definitions
│   └── provisioning/       # Auto-provisioning configs
├── elasticsearch/          # Elasticsearch and Logstash configuration
│   └── logstash.conf       # Log processing rules
└── alertmanager/           # Alert notification configuration
└── config.yml              # Alertmanager configuration

## Components

### Prometheus

The Prometheus configuration scrapes metrics from various services including:
- Cloud Platform application metrics
- Node-level system metrics
- Database metrics
- Redis metrics

### Grafana Dashboards

The following dashboards are provided:
- Overview Dashboard: General application and system metrics
- Security Dashboard: Security-related metrics and incidents
- Cloud Resources Dashboard: Cloud resource usage and provisioning metrics
- ICS Dashboard: Industrial Control System monitoring

### Alertmanager

Alert notification configuration with support for:
- Email notifications
- PagerDuty integration
- Team-based routing
- Alert grouping and inhibition

### Elasticsearch & Logstash

Log centralization and processing for:
- Application logs
- Error logs
- Security logs
- Audit logs

## Deployment

These configurations are designed to be deployed with the application using Kubernetes, Docker Compose, or cloud provider services.

### Kubernetes Deployment

```bash
kubectl apply -f deployment/kubernetes/monitoring/
```

### Docker Compose Deployment

```bash
docker-compose -f docker-compose.monitoring.yml up -d
```

## Environment Variables

Certain sensitive configurations should be provided via environment variables:

- `PROMETHEUS_USERNAME`: Basic auth username for Prometheus
- `PROMETHEUS_PASSWORD`: Basic auth password for Prometheus
- `SMTP_USERNAME`: SMTP username for alert emails
- `SMTP_PASSWORD`: SMTP password for alert emails
- `PAGERDUTY_KEY`: PagerDuty service key
- `PAGERDUTY_SECURITY_KEY`: PagerDuty service key for security team

## 11. `docker-compose.monitoring.yml`

```yaml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:v2.40.0
    container_name: prometheus
    volumes:
      - ./prometheus:/etc/prometheus
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=15d'
    ports:
      - "9090:9090"
    restart: unless-stopped
    networks:
      - monitoring

  alertmanager:
    image: prom/alertmanager:v0.24.0
    container_name: alertmanager
    volumes:
      - ./alertmanager:/etc/alertmanager
      - alertmanager_data:/alertmanager
    command:
      - '--config.file=/etc/alertmanager/config.yml'
      - '--storage.path=/alertmanager'
    ports:
      - "9093:9093"
    restart: unless-stopped
    networks:
      - monitoring

  grafana:
    image: grafana/grafana:9.3.0
    container_name: grafana
    volumes:
      - ./grafana/provisioning:/etc/grafana/provisioning
      - ./grafana/dashboards:/var/lib/grafana/dashboards
      - grafana_data:/var/lib/grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD:-admin}
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_SERVER_ROOT_URL=%(protocol)s://%(domain)s:%(http_port)s/grafana/
      - GF_SERVER_SERVE_FROM_SUB_PATH=true
    ports:
      - "3000:3000"
    restart: unless-stopped
    networks:
      - monitoring

  node-exporter:
    image: prom/node-exporter:v1.4.0
    container_name: node-exporter
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.rootfs=/rootfs'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
    restart: unless-stopped
    networks:
      - monitoring

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.16.0
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - ES_JAVA_OPTS=-Xms512m -Xmx512m
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"
    restart: unless-stopped
    networks:
      - monitoring

  logstash:
    image: docker.elastic.co/logstash/logstash:7.16.0
    container_name: logstash
    volumes:
      - ./elasticsearch/logstash.conf:/usr/share/logstash/pipeline/logstash.conf:ro
      - /var/log/cloud-platform:/var/log/cloud-platform:ro
    depends_on:
      - elasticsearch
    environment:
      - ENVIRONMENT=${ENVIRONMENT:-production}
    restart: unless-stopped
    networks:
      - monitoring

  kibana:
    image: docker.elastic.co/kibana/kibana:7.16.0
    container_name: kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
    restart: unless-stopped
    networks:
      - monitoring

  redis-exporter:
    image: oliver006/redis_exporter:v1.43.0
    container_name: redis-exporter
    environment:
      - REDIS_ADDR=redis://redis:6379
    restart: unless-stopped
    networks:
      - monitoring
      - default

  postgres-exporter:
    image: wrouesnel/postgres_exporter:latest
    container_name: postgres-exporter
    environment:
      - DATA_SOURCE_NAME=postgresql://${POSTGRES_USER:-postgres}:${POSTGRES_PASSWORD:-postgres}@postgres:5432/${POSTGRES_DB:-cloud_platform}?sslmode=disable
    restart: unless-stopped
    networks:
      - monitoring
      - default

networks:
  monitoring:
    driver: bridge
  default:
    external: true
    name: cloud-platform_default

volumes:
  prometheus_data:
  alertmanager_data:
  grafana_data:
  elasticsearch_data: