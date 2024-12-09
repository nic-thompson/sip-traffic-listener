import { formatSIPMessage } from './formatSIPMessage';
import pcap from 'pcap';
import { extractSIPMessage } from './extractSIPMessage';
import { reassembleTCPStream } from './reassembleTCPStream';

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
            console.log(`Listening on ${this.networkInterface} with filter '${this.filter}'...`);
        } catch (error) {
            console.error('Failed to create pcap session:', error);
            process.exit(1);
        }
    }

    start() {
        if (typeof this.session.on !== 'function') {
            console.error("Session 'on' method not available");
            return;
        }

        this.session.on('packet', (rawPacket: Buffer) => {
            console.log('Raw packet captured.');

            try {
                const decodedPacket = pcap.decode(rawPacket);

                if (decodedPacket.payload?.protocol === 6) { // TCP Protocol
                    const completeMessage = reassembleTCPStream(decodedPacket, this.tcpStreams);
                    if (completeMessage) {
                        console.log('Complete SIP Message:', completeMessage);
                        console.log('Formatted SIP Message:\n', formatSIPMessage(completeMessage));
                    }
                } else {
                    const sipMessage = extractSIPMessage(decodedPacket);
                    if (sipMessage) {
                        console.log('Extracted SIP Message:', sipMessage);
                        console.log('Formatted SIP Message:\n', formatSIPMessage(sipMessage));
                    } else {
                        console.warn('No SIP message found in the packet.');
                    }
                }
            } catch (error) {
                console.error('Failed to decode packet:', error);
            }
        });
    }

    stop() {
        try {
            this.session.close();
            console.log('Packet capture session stopped.');
        } catch (error) {
            console.error('Failed to close session', error);
            throw new Error('Failed to close session');
        }
    }
}
