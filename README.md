# install TheHive + Cortex (Incident Response) on ubuntu 24.04 and Kali linux

TheHive and Cortex provide a powerful open-source platform for incident response, with TheHive handling cases and Cortex performing analysis. Both Debian-based distributions like Ubuntu 24.04 and Kali Linux support package-based installation following official StrangeBee documentation. Use separate Elasticsearch instances for each to avoid compatibility issues.[^1_1][^1_2]

## Prerequisites

Install common dependencies on both Ubuntu 24.04 and Kali Linux:

```
sudo apt update
sudo apt install wget curl gnupg coreutils apt-transport-https git ca-certificates ca-certificates-java software-properties-common python3-pip lsb-release unzip
```

Install Java 11 (Amazon Corretto recommended):

```
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" | sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME=\"/usr/lib/jvm/java-11-amazon-corretto\" | sudo tee -a /etc/environment
export JAVA_HOME=\"/usr/lib/jvm/java-11-amazon-corretto\"
java -version  # Verify OpenJDK 11
```

These steps ensure Java 11 compatibility required by both tools.[^1_2][^1_1]

## Ubuntu 24.04 Installation

Follow official steps for Cassandra (TheHive), Elasticsearch (both), TheHive, and Cortex. For TheHive: Install Cassandra 4.1.x from Apache repo, configure `/etc/cassandra/cassandra.yaml` (cluster_name: 'thp', authenticator: PasswordAuthenticator), start service, set passwords, create 'thehive' keyspace/role. Install Elasticsearch 8.x, configure `/etc/elasticsearch/elasticsearch.yml` (cluster.name: hive, xpack.security.enabled: true), set JVM heap (e.g., -Xms4g -Xmx4g), create 'thehive' user/role. Download/verify/install latest TheHive DEB (e.g., from https://thehive.download.strangebee.com), edit `/etc/thehive/application.conf` with DB creds, start service (port 9000). Repeat for Cortex with separate ES (port 9001).[^1_3][^1_4][^1_1]

On Kali Linux, use the same DEB/RPM/manual steps as Ubuntu since it's Debian-based; TheHive is also in Kali repos (`sudo apt install thehive`), but verify version and manually install Cortex via DEB download/verify/GPG check/install as above. Docker is an alternative for Kali to avoid conflicts: `docker-compose up` with official stacks.[^1_5][^1_6][^1_2]

## Configuration Notes

Edit `/etc/thehive/application.conf` and `/etc/cortex/application.conf` for Cassandra/Elasticsearch creds, secret keys, and ports. Enable services: `sudo systemctl enable --now cassandra elasticsearch thehive cortex`. Access TheHive at http://localhost:9000, Cortex at :9001; complete first-run wizards. Use Docker for analyzers (`sudo usermod -aG docker cortex`).[^1_1][^1_2]

## Verification

Check services: `sudo systemctl status thehive cortex elasticsearch cassandra`. Test versions: `thehive --version`, `cortex --version`. Firewall: `sudo ufw allow 9000,9001,9200` (adjust for security).[^1_2][^1_1]
<span style="display:none">[^1_10][^1_7][^1_8][^1_9]</span>

<div align="center">⁂</div>

[^1_1]: https://docs.strangebee.com/thehive/installation/installation-guide-linux-standalone-server/

[^1_2]: https://letsdefend.io/blog/how-to-install-thehive-on-linux

[^1_3]: https://docs.strangebee.com/thehive/installation/installation-methods/

[^1_4]: https://www.howtoforge.com/how-to-install-cortex-on-ubuntu-22-04/

[^1_5]: https://systemweakness.com/new-tools-new-errors-deploying-thehive-cortex-on-kali-linux-with-docker-6467385c318a

[^1_6]: https://gitlab.com/kalilinux/packages/thehive

[^1_7]: https://kifarunix.com/install-thehive-on-ubuntu/

[^1_8]: https://xsoar.pan.dev/docs/reference/integrations/the-hive-project

[^1_9]: https://docs.strangebee.com/cortex/installation-and-configuration/step-by-step-guide/

[^1_10]: https://shape.host/resources/optimize-threat-analysis-install-cortex-observable-ubuntu-2204


---

# System requirements for TheHive and Cortex on Ubuntu 24.04

TheHive and Cortex have scalable hardware requirements based on concurrent users, data volume, and deployment type (standalone or clustered). Ubuntu 24.04 LTS is officially supported for both. Minimum setups start small but scale for production.[^2_1][^2_2][^2_3]

## TheHive Requirements

For standalone deployments on Ubuntu 24.04 (TheHive + Cassandra + Elasticsearch on one machine), allocate resources per concurrent users:


| Concurrent Users | TheHive | Cassandra | Elasticsearch |
| :-- | :-- | :-- | :-- |
| <10 | 3 cores / 4 GB | 3 cores / 4 GB | 3 cores / 4 GB |
| <20 | 3-4 cores / 6 GB | 3-4 cores / 6 GB | 3-4 cores / 6 GB |
| <50 | 4-6 cores / 8 GB | 4-6 cores / 8 GB | 4-6 cores / 8 GB |

Docker Compose profiles recommend 8 GB RAM/4 vCPUs for testing, 16 GB/4 vCPUs for standard production, and 32 GB/8 vCPUs for high-performance. Storage: 100-150 GB SSD for most cases.[^2_3][^2_1]

## Cortex Requirements

Start with dedicated resources: 8 vCPUs and 16 GB RAM, scaling based on analyzer usage and data volume. Requires Java 11+ and Elasticsearch 8.x (separate from TheHive's for best practice).[^2_4][^2_2]

## Additional Notes

Elasticsearch heap should be ≤50% of system RAM (e.g., 6 GB on 12 GB total). Monitor utilization and scale vertically/horizontally. Combined TheHive+Cortex standalone needs ~16-32 GB RAM/8+ cores for moderate use.[^2_2][^2_1][^2_3]
<span style="display:none">[^2_10][^2_11][^2_5][^2_6][^2_7][^2_8][^2_9]</span>

<div align="center">⁂</div>

[^2_1]: https://docs.strangebee.com/thehive/installation/system-requirements/

[^2_2]: https://letsdefend.io/blog/how-to-install-thehive-on-linux

[^2_3]: https://docs.strangebee.com/thehive/installation/installation-guide-linux-standalone-server/

[^2_4]: https://docs.strangebee.com/cortex/installation-and-configuration/

[^2_5]: https://github.com/TheHive-Project/TheHive/wiki/Home/e16a264681be6f8022cd745867b840015bba4f5f

[^2_6]: https://www.pickgamer.com/games/the-hive/requirements

[^2_7]: https://www.systemrequirementslab.com/cyri/requirements/the-hive/14593

[^2_8]: https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Hardware-requirements

[^2_9]: https://kifarunix.com/install-thehive-on-ubuntu/

[^2_10]: https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.5/Cortex-XSOAR-On-prem-Documentation/System-Requirements

[^2_11]: https://haxcript.wordpress.com/2020/06/20/installing-thehive-in-debian-linux/


---

# Step-by-step Docker Compose install for TheHive and Cortex on Kali

Docker Compose provides an easy way to deploy TheHive and Cortex on Kali Linux using official StrangeBee profiles. This method bundles Cassandra, Elasticsearch, TheHive, Cortex, and Nginx in containers. It works seamlessly on Kali as a Debian derivative with Docker installed.[^3_1][^3_2][^3_3]

## Prerequisites

Install Docker Engine (v23.0+) and Compose plugin (v2.20+), plus jq:

```
sudo apt update
sudo apt install docker.io docker-compose jq git
sudo systemctl enable --now docker
sudo usermod -aG docker $USER  # Log out/in
docker run hello-world  # Verify
docker compose version
```

Meets minimum: 8 GB RAM/4 vCPUs for testing.[^3_2][^3_3]

## Step-by-Step Deployment

1. Clone the official repo:

```
git clone https://github.com/StrangeBeeCorp/docker.git
cd docker
```

2. Choose profile (e.g., testing with TheHive+Cortex):

```
cd test-thehive-cortex  # Or prod1-thehive-cortex
```

3. Initialize environment (sets secrets, certs, .env, permissions):

```
bash ./scripts/init.sh
```

Follow prompts for server name; uses self-signed certs by default.[^3_2]
4. Start stack:

```
docker compose up -d
```

View logs if issues: `docker compose up` or `docker compose logs -f`.[^3_3][^3_2]

## Access and Verification

Access TheHive at https://localhost/thehive (or IP), Cortex at /cortex (self-signed cert warning expected). Verify: `docker compose ps`, `docker compose logs thehive`. Firewall: `sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT` or disable for local. Customize configs in ./thehive/config/application.conf, restart container.[^3_1][^3_3][^3_2]
<span style="display:none">[^3_10][^3_4][^3_5][^3_6][^3_7][^3_8][^3_9]</span>

<div align="center">⁂</div>

[^3_1]: https://systemweakness.com/new-tools-new-errors-deploying-thehive-cortex-on-kali-linux-with-docker-6467385c318a

[^3_2]: https://docs.strangebee.com/thehive/installation/installation-guide-linux-standalone-server/

[^3_3]: https://docs.strangebee.com/thehive/installation/docker/

[^3_4]: https://letsdefend.io/blog/how-to-install-thehive-on-linux

[^3_5]: https://www.youtube.com/watch?v=Vr4flc55S5c

[^3_6]: https://github.com/TheHive-Project/TheHive/wiki/Docker-guide/e38ebc0088049dc3377dc046c18856752623b790

[^3_7]: https://docs.strangebee.com/cortex/installation-and-configuration/run-cortex-with-docker/

[^3_8]: https://hub.docker.com/r/thehiveproject/thehive

[^3_9]: https://github.com/TheHive-Project/Docker-Templates

[^3_10]: https://thehive-project.github.io/Cortex-Analyzers/dev_guides/dockerize-your-custom-analyzers-responders/


---

# How to configure SSL certificates for TheHive and Cortex

TheHive and Cortex recommend using a reverse proxy like Nginx for SSL/TLS termination to simplify certificate management. Official Docker deployments generate self-signed certs by default during init. Replace with Let's Encrypt or custom certs for production.[^4_1][^4_2][^4_3]

## Docker Compose SSL Setup

Docker stacks include Nginx reverse proxy (ports 80/443). Self-signed certs are auto-generated:

```
bash ./scripts/init.sh  # Prompts for domain, generates certs/secrets
docker compose up -d
```

Access https://your-domain (ignore browser warning) or https://your-domain/thehive, /cortex.[^4_3][^4_4]

## Replace with Let's Encrypt

1. Install certbot:

```
sudo apt install certbot
```

2. Stop stack: `docker compose down`
3. Obtain certs (standalone mode):

```
sudo certbot certonly --standalone -d your-domain.com
# Certs at /etc/letsencrypt/live/your-domain.com/fullchain.pem, privkey.pem
```

4. Mount certs in docker-compose.yml (under nginx service):

```
volumes:
  - /etc/letsencrypt/live/your-domain.com/fullchain.pem:/etc/nginx/ssl/nginx.crt:ro
  - /etc/letsencrypt/live/your-domain.com/privkey.pem:/etc/nginx/ssl/nginx.key:ro
```

5. Set environment vars in .env (from init.sh):

```
CERT_PATH=/etc/nginx/ssl/nginx.crt
CERT_KEY_PATH=/etc/nginx/ssl/nginx.key
```

6. Restart: `docker compose up -d`[^4_2][^4_1][^4_3]

## Bare-Metal Nginx Proxy

Install Nginx: `sudo apt install nginx`. Create /etc/nginx/sites-available/thehive.conf:

```
server {
  listen 443 ssl http2;
  server_name your-domain.com;
  ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
  location /thehive {
    proxy_pass http://127.0.0.1:9000/;
    # Add timeouts, HSTS as in docs
  }
}
```

Similar for Cortex (/cortex -> :9001). Enable: `ln -s /etc/nginx/sites-available/thehive.conf /etc/nginx/sites-enabled/ && nginx -t && systemctl reload nginx`. Update TheHive app.conf baseUrl = "https://your-domain.com/thehive".[^4_5][^4_1][^4_2]

## Renewal and Notes

Automate renewal: `sudo crontab -e` with `certbot renew && docker compose restart nginx`. For custom CAs, add to system trust: `apt install ca-certificates-java; cp ca.crt /usr/share/ca-certificates/extra/; dpkg-reconfigure ca-certificates; systemctl restart cortex thehive`. Use HSTS header for security.[^4_6][^4_1][^4_5]
<span style="display:none">[^4_10][^4_11][^4_12][^4_13][^4_7][^4_8][^4_9]</span>

<div align="center">⁂</div>

[^4_1]: https://docs.strangebee.com/cortex/installation-and-configuration/ssl/

[^4_2]: https://docs.strangebee.com/thehive/configuration/ssl/configure-https-reverse-proxy/

[^4_3]: https://docs.strangebee.com/thehive/installation/installation-guide-linux-standalone-server/

[^4_4]: https://docs.strangebee.com/thehive/installation/docker/

[^4_5]: https://letsdefend.io/blog/how-to-install-thehive-on-linux

[^4_6]: https://docs.strangebee.com/thehive/configuration/ssl/

[^4_7]: https://docs.strangebee.com/thehive/configuration/ssl/configure-ssl-jvm/

[^4_8]: https://github.com/TheHive-Project/Cortex/issues/373

[^4_9]: https://blog.thehive-project.org/tag/ssl/

[^4_10]: https://docs.strangebee.com/thehive/configuration/ssl/ssl-thehive-configuration-settings/

[^4_11]: https://blog.agood.cloud/posts/2019/04/24/setup-reverse-proxy-for-thehive/

[^4_12]: https://artifacthub.io/packages/helm/strangebee-helm/thehive

[^4_13]: https://blog.agood.cloud/posts/2019/09/26/setup-reverse-proxy-for-cortex/


---

# Open required firewall ports on Ubuntu 24.04 for TheHive Cortex

**Ubuntu 24.04 uses UFW for firewall management by default.** Open ports for TheHive and Cortex based on deployment type (bare-metal or Docker). Essential ports include web UI, databases, and transport for internal communication.[^5_1][^5_2]

## Bare-Metal Deployment Ports

Allow these TCP ports for standalone setup (adjust if clustered):


| Service/Component | Port | Purpose |
| :-- | :-- | :-- |
| TheHive | 9000 | Web UI (HTTP) |
| Cortex | 9001 | Web UI (HTTP) |
| Elasticsearch | 9200 | HTTP API |
| Elasticsearch | 9300 | Transport (node-to-node) |
| Cassandra | 7000 | Internode |
| Cassandra | 9042 | CQL client |
| Nginx (optional) | 80/443 | Reverse proxy/HTTPS |

Commands:

```
sudo ufw allow 9000/tcp  # TheHive
sudo ufw allow 9001/tcp  # Cortex
sudo ufw allow 9200/tcp  # ES HTTP
sudo ufw allow 9300/tcp  # ES transport
sudo ufw allow 9042/tcp  # Cassandra
sudo ufw reload
sudo ufw status verbose
```

Limit to specific IPs: `sudo ufw allow from 192.168.1.0/24 to any port 9000 proto tcp`.[^5_2][^5_1]

## Docker Compose Ports

Official stacks expose only external ports via Nginx reverse proxy (80/443 TCP for HTTP/HTTPS). Internal ports (9000,9001,9200,etc.) bind to localhost/container network—no firewall needed externally.

```
sudo ufw allow 80/tcp   # HTTP redirect
sudo ufw allow 443/tcp  # HTTPS UI
sudo ufw reload
```

Docker publishes 443/tcp; confirm with `docker compose ps`.[^5_5][^5_6][^5_1]

## Security Best Practices

- Use HTTPS (443) exclusively; block 9000/9001 externally.
- Restrict DB ports (9200,9042,9300,7000) to localhost: `sudo ufw allow from 127.0.0.1 to any port 9200`.
- Analyzers may need outbound internet (e.g., VirusTotal API)—no inbound ports.
- Enable UFW: `sudo ufw enable` (deny by default).[^5_7][^5_1][^5_2]
<span style="display:none">[^5_10][^5_11][^5_12][^5_8][^5_9]</span>

<div align="center">⁂</div>

[^5_1]: https://docs.strangebee.com/thehive/installation/installation-guide-linux-standalone-server/

[^5_2]: https://letsdefend.io/blog/how-to-install-thehive-on-linux

[^5_3]: https://github.com/TheHive-Project/TheHive/issues/480

[^5_4]: https://github.com/TheHive-Project/Cortex/issues/288

[^5_5]: https://hub.docker.com/r/thehiveproject/thehive

[^5_6]: https://docs.strangebee.com/thehive/installation/docker/

[^5_7]: https://docs.strangebee.com/cortex/installation-and-configuration/ssl/

[^5_8]: https://docs.strangebee.com/cortex/installation-and-configuration/

[^5_9]: https://docs-cortex.paloaltonetworks.com/r/Cortex-XPANSE/2/Cortex-Xpanse-Expander-User-Guide/Scanning-ports-and-protocols

[^5_10]: https://blog.thehive-project.org/tag/assessment/

[^5_11]: https://github.com/TheHive-Project/TheHive/wiki/Installation-guide/067d3b5bb65116e7a3dc7c5e7e05d7926d70e5fc

[^5_12]: https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.11/Cortex-XSOAR-On-prem-Documentation/Port-requirements-for-cluster-communication?contentId=Fw5B6g_bHsCYhfj_5yCi8Q


---

# Integrate Cortex analyzers and MISP with TheHive setup guide

Cortex analyzers integrate automatically with TheHive for observable enrichment, while MISP connects via TheHive's built-in connector for event import/export. Use official catalogs for analyzers/responders or host installs; Docker simplifies dependencies. Follow these steps post-installation.[^6_1][^6_2]

## Install Cortex Analyzers

For Docker (recommended):

- Add Docker group: `sudo usermod -aG docker cortex` (bare-metal) or ensure container perms.
- Edit `/etc/cortex/application.conf` or docker .env:

```
analyzer {
  urls = ["https://catalogs.download.strangebee.com/latest/json/analyzers.json"]
}
responder {
  urls = ["https://catalogs.download.strangebee.com/latest/json/responders.json"]
}
```

- Restart: `sudo systemctl restart cortex` or `docker compose restart cortex`.
For host programs (bare-metal):

```
sudo apt install python3-pip python3-dev ssdeep libfuzzy-dev libimage-exiftool-perl libmagic1 build-essential git libssl-dev
cd /opt && git clone https://github.com/TheHive-Project/Cortex-Analyzers && sudo chown -R cortex:cortex /opt/Cortex-Analyzers
for I in $(find Cortex-Analyzers -name 'requirements.txt'); do sudo -H pip3 install -r $I || true; done
```

Add `/opt/Cortex-Analyzers/analyzers` to analyzer.urls in conf, restart Cortex. Verify in Cortex UI > Organization > Analyzers (enable/select).[^6_3][^6_2][^6_1]

## Enable in TheHive

In TheHive UI (admin):

- Go to Organization > Integrations > Cortex.
- Add Cortex URL (e.g., http://localhost:9001), API key (from Cortex > Org > Settings > API Keys).
- Test connection; analyzers appear in case observables' "Analyze" menu.[^6_4][^6_2]


## MISP Integration

1. In MISP UI (admin): Administration > List Auth Keys > Add key (read/write, no expiry, note IP).
2. In TheHive `/etc/thehive/application.conf`:

```
misp {
  interval: 2m
  servers: [
    name = "MISP Server"
    url  = "https://misp.example.com"
    auth {
      type = key
      key  = "YOUR_MISP_API_KEY"
    }
  ]
}
```

3. Restart TheHive: `sudo systemctl restart thehive`.
4. Verify: MISP icon green in TheHive UI bottom-left; auto-imports published events. Export cases to MISP via actions.[^6_5][^6_6]

## Verification and Tips

Test analyzer: Create case/observable in TheHive, run "All analyzers". MISP syncs every 2m. Custom analyzers go in /opt/Custom-Analyzers. Scale executor parallelism for load.[^6_2][^6_1][^6_5]
<span style="display:none">[^6_10][^6_11][^6_7][^6_8][^6_9]</span>

<div align="center">⁂</div>

[^6_1]: https://docs.strangebee.com/cortex/installation-and-configuration/analyzers-responders/

[^6_2]: https://docs.strangebee.com/thehive/installation/installation-guide-linux-standalone-server/

[^6_3]: https://thehive-project.github.io/Cortex-Analyzers/

[^6_4]: https://github.com/TheHive-Project/Cortex

[^6_5]: https://kifarunix.com/how-to-integrate-thehive-with-misp/

[^6_6]: https://www.youtube.com/watch?v=kyH1rkK6ch4

[^6_7]: https://strangebee.com/blog/cortex-analyzers-3-5-0-microsoft-entra-id-integration-yara-and-more/

[^6_8]: https://docs.sekoia.io/cti/features/integrations/thehive/

[^6_9]: https://github.com/pjuhas/Cortex-Analyzers

[^6_10]: https://docs.domaintools.com/integrations/thehive/thehive-cortex/

[^6_11]: https://github.com/TheHive-Project/docs/blob/main/docs/cortex/installation-and-configuration/analyzers-responders.md


---

# Add Cortex analyzers to TheHive application.conf on Ubuntu

To enable Cortex analyzers in TheHive on Ubuntu 24.04, configure the connection in TheHive's `application.conf` file. This links TheHive to Cortex, making analyzers available for observables without altering Cortex's analyzer settings. Analyzers must be pre-installed/enabled in Cortex first.[^7_1][^7_2][^7_3]

## Locate and Edit Config

The file is at `/etc/thehive/application.conf`. Backup first:

```
sudo cp /etc/thehive/application.conf /etc/thehive/application.conf.bak
sudo nano /etc/thehive/application.conf  # Or vim/editor
```

Uncomment/enable the Cortex module near the top:

```
play.modules.enabled += org.thp.thehive.connector.cortex.CortexModule
```

Find or add the `cortex` section (usually under connectors).[^7_2][^7_1]

## Add Cortex Server

Insert/update the `cortex` block with your Cortex details (replace placeholders):

```
cortex {
  servers: [
    {
      name = "Local Cortex"
      url  = "http://localhost:9001"  # Or https://your-domain/cortex
      auth {
        type = "bearer"
        key  = "your-cortex-org-api-key"  # From Cortex UI > Org > Settings > API Keys
      }
      wsConfig {}  # For WebSocket if needed
    }
  ]
}
```

Obtain API key: Log into Cortex > Organization > Settings > API Keys > Create (no expiry).[^7_3][^7_4][^7_1][^7_2]

## Apply Changes

Validate syntax (optional: `thehive -Dconfig.file=/etc/thehive/application.conf -Dhttp.port=9000`), then restart:

```
sudo systemctl restart thehive
sudo systemctl status thehive  # Check logs: journalctl -u thehive -f
```

In TheHive UI (admin): Organization > Integrations > Cortex shows green status. Analyzers appear in case observables' "Analyze" menu.[^7_1][^7_3]

## Troubleshooting

- Error "Cortex unavailable": Verify URL/key, firewall (9001 open), Cortex running.
- No analyzers: Ensure Cortex has them enabled (Cortex UI > Org > Analyzers).
- HTTPS: Use full proxy path if behind Nginx (e.g., /cortex).[^7_5][^7_1]
<span style="display:none">[^7_10][^7_11][^7_6][^7_7][^7_8][^7_9]</span>

<div align="center">⁂</div>

[^7_1]: https://blog.agood.cloud/posts/2019/09/27/integrate-thehive-and-cortex/

[^7_2]: http://docs.thehive-project.org/thehive/installation-and-configuration/configuration/connectors-cortex/

[^7_3]: https://kifarunix.com/easy-way-to-integrate-thehive-with-cortex/

[^7_4]: https://letsdefend.io/blog/how-to-install-thehive-on-linux

[^7_5]: https://docs.strangebee.com/cortex/installation-and-configuration/analyzers-responders/

[^7_6]: https://github.com/TheHive-Project/Cortex/blob/master/conf/application.sample

[^7_7]: https://docs.strangebee.com/cortex/installation-and-configuration/

[^7_8]: https://thehive-project.github.io/Cortex-Analyzers/admin_guides/manage-private-custom-analyzers-responders/

[^7_9]: https://blog.devgenius.io/soc-implementation-with-thehive-cortex-elasticsearch-672e89219f0c

[^7_10]: https://blog.thehive-project.org/tag/cortex/

[^7_11]: https://docs.strangebee.com/cortex/installation-and-configuration/step-by-step-guide/

