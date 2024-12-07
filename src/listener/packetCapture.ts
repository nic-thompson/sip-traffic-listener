import pcap from 'pcap';
import { extractSIPMessage } from './extractSIPMessage';



export class PacketCaptureModule {
    private session: any;
    private networkInterface: string;
    private filter: string;
    private tcpStreams: Map<string, Buffer> = new Map();

    constructor(networkInterface: string, filter: string = 'tcp port 5060') {
        this.networkInterface = networkInterface;
        this.filter = filter;

        try {
            this.session = pcap.createSession(this.networkInterface, { filter: this.filter });
            console.log((`Listening on ${this.networkInterface} with filter '${this.filter}'...`));
        } catch (error) {
            console.error(('Failed to create pcap session:'), error);
            process.exit(1);
        }
    }

    start() {
        if (typeof this.session.on !== 'function') {
            console.error(("Session 'on' method not available"));
            return;
        }

        this.session.on('packet', (rawPacket: Buffer) => {
            console.log(('Raw packet captured.'));

            try {
                const decodedPacket = pcap.decode(rawPacket);

                if (decodedPacket.payload?.protocol !== 6) {
                    console.log(('Decoded packet (non-TCP):'), decodedPacket);
                }

                if (decodedPacket.payload?.protocol === 6) {
                    const completeMessage = this.reassembleTCPStream(decodedPacket);
                    if (completeMessage) {
                        console.log(('Complete SIP Message:'), completeMessage);
                    }
                } else {
                    const sipMessage = extractSIPMessage(decodedPacket);
                    if (sipMessage) {
                        console.log(('Extracted SIP Message:'), sipMessage);
                    } else {
                        console.warn(('No SIP message found in the packet.'));
                    }
                }
            } catch (error) {
                console.error(('Failed to decode packet:'), error);
            }
        });
    }

    stop() {
        try {
            this.session.close();
            console.log(('Packet capture session stopped.'));
        } catch (error) {
            console.error(('Failed to close session'), error);
            throw new Error('Failed to close session');
        }
    }

    public reassembleTCPStream(packet: any): string | null {
        const src = packet.payload?.saddr;
        const dst = packet.payload?.daddr;
        const sport = packet.payload?.payload?.sport;
        const dport = packet.payload?.payload?.dport;

        if (!src || !dst || !sport || !dport || !packet.payload?.payload?.payload) {
            return null;
        }

        const streamKey = `${src}:${sport}-${dst}:${dport}`;
        const tcpPayload = packet.payload.payload.payload;

        const currentBuffer = this.tcpStreams.get(streamKey) || Buffer.alloc(0);
        const updatedBuffer = Buffer.concat([currentBuffer, tcpPayload]);

        const message = updatedBuffer.toString('utf-8');

        if (message.includes('\r\n\r\n')) {
            const headersEndIndex = message.indexOf('\r\n\r\n');
            const headers = message.substring(0, headersEndIndex);
            const contentLengthMatch = headers.match(/Content-Length:\s*(\d+)/i);

            if (contentLengthMatch) {
                const contentLength = parseInt(contentLengthMatch[1], 10);
                const bodyStartIndex = headersEndIndex + 4;
                const body = message.substring(bodyStartIndex);

                if (body.length >= contentLength) {
                    this.tcpStreams.delete(streamKey);
                    return message;
                }
            } else {
                this.tcpStreams.delete(streamKey);
                return message.substring(0, headersEndIndex + 4);
            }
        }

        this.tcpStreams.set(streamKey, updatedBuffer);
        return null;
    }

    public formatSIPMessage(sipMessage: string | null | undefined): string {
        if (!sipMessage) {
            return '';
        }
        const lines = sipMessage.split(/\r?\n/).filter(line => line.trim() !== '');
        return lines.map((line, index) => `${index + 1}: ${line}`).join('\n');
    }
}
