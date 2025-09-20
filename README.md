# LibHdHomerun-Docker

[![GitHub CI](https://github.com/lferrarotti74/LibHdHomerun-Docker/workflows/Build%20release%20image/badge.svg)](https://github.com/lferrarotti74/LibHdHomerun-Docker/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/lferrarotti74/LibHdHomerun-Docker)](https://github.com/lferrarotti74/LibHdHomerun-Docker/releases)
[![Docker Hub](https://img.shields.io/docker/pulls/lferrarotti74/libhdhomerun-docker)](https://hub.docker.com/r/lferrarotti74/libhdhomerun-docker)
[![Docker Image Size](https://img.shields.io/docker/image-size/lferrarotti74/libhdhomerun-docker/latest)](https://hub.docker.com/r/lferrarotti74/libhdhomerun-docker)
[![GitHub](https://img.shields.io/github/license/lferrarotti74/LibHdHomerun-Docker)](LICENSE)

<!-- SonarQube Badges -->
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=lferrarotti74_LibHdHomerun-Docker&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=lferrarotti74_LibHdHomerun-Docker)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=lferrarotti74_LibHdHomerun-Docker&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=lferrarotti74_LibHdHomerun-Docker)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=lferrarotti74_LibHdHomerun-Docker&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=lferrarotti74_LibHdHomerun-Docker)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=lferrarotti74_LibHdHomerun-Docker&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=lferrarotti74_LibHdHomerun-Docker)

A Docker container for the [Silicondust libhdhomerun](https://github.com/Silicondust/libhdhomerun) library and `hdhomerun_config` command-line utility. This container provides an easy way to interact with and control HDHomeRun TV tuners from Silicondust without needing to compile the library on your host system.

## What is LibHdHomerun?

LibHdHomerun is the official library from Silicondust that implements the HDHomeRun protocol for controlling HDHomeRun TV tuners. The library includes the `hdhomerun_config` command-line utility which allows you to:

- Discover HDHomeRun devices on your network
- Configure tuner settings
- Scan for channels
- Monitor tuner status
- Control streaming and recording

## Quick Start

### Pull the Docker Image

```bash
docker pull lferrarotti74/libhdhomerun-docker:latest
```

### Run the Container

```bash
docker run --rm --network host lferrarotti74/libhdhomerun-docker:latest /libhdhomerun/hdhomerun_config discover
```

## Usage Examples

### Discover HDHomeRun Devices

Find all HDHomeRun devices on your network:

```bash
# Discover all devices
docker run --rm --network host lferrarotti74/libhdhomerun-docker:latest /libhdhomerun/hdhomerun_config discover

# Discover specific device by IP
docker run --rm --network host lferrarotti74/libhdhomerun-docker:latest /libhdhomerun/hdhomerun_config discover 192.168.1.100
```

### Get Device Information

```bash
# Get help for available commands (by IP address)
docker run --rm --network host lferrarotti74/libhdhomerun-docker:latest /libhdhomerun/hdhomerun_config 192.168.1.100 get help

# Get help for available commands (by Device ID)
docker run --rm --network host lferrarotti74/libhdhomerun-docker:latest /libhdhomerun/hdhomerun_config 12410A5D get help

# Get firmware version
docker run --rm --network host lferrarotti74/libhdhomerun-docker:latest /libhdhomerun/hdhomerun_config 192.168.1.100 get /sys/version

# Get device model
docker run --rm --network host lferrarotti74/libhdhomerun-docker:latest /libhdhomerun/hdhomerun_config 192.168.1.100 get /sys/model
```

### Tuner Operations

```bash
# Get tuner status
docker run --rm --network host lferrarotti74/libhdhomerun-docker:latest /libhdhomerun/hdhomerun_config 192.168.1.100 get /tuner0/status

# Set channel map for tuner
docker run --rm --network host lferrarotti74/libhdhomerun-docker:latest /libhdhomerun/hdhomerun_config 192.168.1.100 set /tuner0/channelmap us-bcast

# Scan for channels
docker run --rm --network host lferrarotti74/libhdhomerun-docker:latest /libhdhomerun/hdhomerun_config 192.168.1.100 scan /tuner0
```

### Using with Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  hdhomerun-config:
    image: lferrarotti74/libhdhomerun-docker:latest
    network_mode: host
    command: ["/libhdhomerun/hdhomerun_config", "discover"]
```

Run with:

```bash
docker-compose run --rm hdhomerun-config /libhdhomerun/hdhomerun_config 192.168.1.100 get /sys/version
```

### Interactive Usage

For multiple commands, you can run the container interactively:

```bash
docker run -it --rm --network host lferrarotti74/libhdhomerun-docker:latest /bin/bash
```

Then inside the container:

```bash
/libhdhomerun/hdhomerun_config discover
/libhdhomerun/hdhomerun_config 192.168.1.100 get help
```

## Available Commands

The `hdhomerun_config` utility supports various commands: <mcreference link="https://info.hdhomerun.com/info/hdhomerun_config" index="1">1</mcreference>

- `discover` - Find HDHomeRun devices
- `get <item>` - Get configuration values
- `set <item> <value>` - Set configuration values
- `scan <tuner>` - Scan for channels
- `save <tuner> <filename>` - Save stream to file
- `upgrade <filename>` - Upgrade firmware

## Network Requirements

- The container uses `--network host` to access HDHomeRun devices on your local network
- HDHomeRun devices must be on the same subnet as the Docker host for device discovery
- You can also address devices directly by IP address if they're on different subnets

## Channel Maps

Supported channel maps for different regions:

**US/Canada:**
- `us-bcast` - Digital Antenna (ATSC)
- `us-cable` - Digital Cable (Normal)
- `us-hrc` - Digital Cable (HRC)
- `us-irc` - Digital Cable (IRC)

**Europe/Australia:**
- `eu-bcast` - Digital Antenna (Europe)
- `eu-cable` - Digital Cable (Europe)
- `au-bcast` - Digital Antenna (Australia)
- `au-cable` - Digital Cable (Australia)

## Building from Source

To build the Docker image yourself:

```bash
git clone https://github.com/lferrarotti74/LibHdHomerun-Docker.git
cd LibHdHomerun-Docker
docker build -t libhdhomerun-docker .
```

## Documentation

- **[Contributing Guidelines](CONTRIBUTING.md)** - How to contribute to the project
- **[Code of Conduct](CODE_OF_CONDUCT.md)** - Community standards and behavior expectations
- **[Security Policy](SECURITY.md)** - How to report security vulnerabilities
- **[Changelog](CHANGELOG.md)** - Version history and release notes
- **[Maintainers](MAINTAINERS.md)** - Project governance and maintainer information
- **[Authors](AUTHORS.md)** - Contributors and acknowledgments

## Contributing

We welcome contributions from the community! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

- **Bug Reports**: Use GitHub issues with detailed information
- **Feature Requests**: Propose enhancements via GitHub issues
- **Code Contributions**: Fork, create feature branch, and submit PR
- **Documentation**: Help improve docs and examples

Please follow our [Code of Conduct](CODE_OF_CONDUCT.md) in all interactions.

## Support

For issues related to this Docker container, please open an issue on [GitHub](https://github.com/lferrarotti74/LibHdHomerun-Docker/issues).

For HDHomeRun device support, please refer to [Silicondust's support resources](https://www.silicondust.com/support/).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Related Links

- [Silicondust libhdhomerun GitHub Repository](https://github.com/Silicondust/libhdhomerun)
- [HDHomeRun Configuration Documentation](https://info.hdhomerun.com/info/hdhomerun_config)
- [Silicondust Official Website](https://www.silicondust.com/)
- [Docker Hub Repository](https://hub.docker.com/r/lferrarotti74/libhdhomerun-docker)