# SIP Traffic Listener

SIP Traffic Listener captures live SIP traffic (e.g. REGISTER / UNREGISTER)
from a network interface using libpcap, reconstructs fragmented TCP streams,
and logs complete SIP messages for monitoring, debugging, or telemetry
integration pipelines.

Designed for deployment on Linux systems via Docker.

---

## Features

- Capture live SIP traffic from a network interface
- Detect REGISTER / UNREGISTER messages
- Reassemble fragmented TCP SIP packets
- Handle malformed packets safely
- Structured logging output
- Docker-based deployment
- Fully unit-tested core parsing pipeline (100% branch coverage)

---

## Quick Start (Docker)

Build the container:

    pnpm docker:build

Export image for transfer (optional):

    pnpm docker:export:listener

Transfer to target machine:

    scp listener_image.tar user@<server-ip>:/home/user/

Load image on target machine:

    sudo docker load -i listener_image.tar

Run container:

    sudo docker run \
      --privileged \
      --network host \
      --restart unless-stopped \
      --name sip-traffic-listener \
      -d sip-traffic-listener

View logs:

    sudo docker logs -f sip-traffic-listener

---

## Local Development

Install dependencies:

    pnpm install

Run tests:

    pnpm test

Build project:

    pnpm build

---

## Example Output

Example SIP REGISTER message detected:

    REGISTER sip:example.com SIP/2.0
    Via: SIP/2.0/UDP 192.168.1.10:5060
    Call-ID: abc123@example.com
    Contact: <sip:user@192.168.1.10>

---

## Configuration

### Network Interface

The capture interface must be configured in the application
(e.g. eth0, eth1, eth2).

Ensure the interface exists and the container has permission
to access it.

### SIP Port

Default:

    5060

Can be modified in source if required.

---

## Requirements

- Linux host
- Docker
- Network interface with SIP traffic visibility
- Root / privileged container permissions
- libpcap-compatible environment

---

## Architecture Overview

Core modules:

    extractSIPMessage.ts     Detect SIP payloads
    reassembleTCPStream.ts   Reconstruct fragmented TCP packets
    packetCapture.ts         Manage capture lifecycle
    formatSIPMessage.ts      Format readable output

These components are fully unit-tested and designed for safe
operation under malformed or incomplete packet conditions.

---

## Use Cases

Typical scenarios include:

- monitoring SIP registrations on VoIP gateways
- debugging endpoint registration failures
- detecting unexpected SIP activity
- feeding SIP metadata into telemetry pipelines
- integrating SIP events into MQTT / Sparkplug infrastructure

---

## Reliability

Core parsing and stream handling logic is protected by:

- 100% statement coverage
- 100% branch coverage
- malformed packet regression tests
- async processing validation

This helps ensure stable operation in real network environments.

---

## Deployment Notes

If redeploying:

Stop container:

    sudo docker stop sip-traffic-listener

Remove container:

    sudo docker rm sip-traffic-listener

Reload image:

    sudo docker load -i listener_image.tar

Restart container using the run command above.

---

## Roadmap

Potential future improvements:

- configurable capture interface via environment variable
- configurable SIP ports
- JSON output mode
- PCAP replay support
- MQTT publishing integration