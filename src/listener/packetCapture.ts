import pcap from 'pcap';

export class PacketCaptureModule {
    private session: any;
    private networkInterface: string;
    private filter: string;
    private tcpStreams: Map<string, Buffer> = new Map(); // Map to store incomplete TCP streams

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
    
                // Log the decoded packet if it's not TCP
                if (decodedPacket.payload?.protocol !== 6) {
                    console.log('Decoded packet:', decodedPacket);
                }
    
                // Process TCP packets for reassembly
                if (decodedPacket.payload?.protocol === 6) {
                    console.log('DEBUG: Entering uncovered line 41');
                    const completeMessage = this.reassembleTCPStream(decodedPacket);
                    if (completeMessage) {
                        console.log('Complete SIP Message:', completeMessage);
                    }
                } else {
                    // Handle SIP extraction for non-TCP packets
                    const sipMessage = this.extractSIPMessage(decodedPacket);
                    if (sipMessage) {
                        console.log('Extracted SIP Message:', sipMessage);
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

    // Change this from `private` to `protected` or `public`
public extractSIPMessage(packet: any): string | null {
    try {
        let payload = packet?.payload;

        // Traverse nested payloads to reach the innermost data
        while (payload && payload.payload) {
            payload = payload.payload;
        }

        if (payload?.data) {
            const sipMessage = payload.data.toString('utf-8').trim();

            // Check if the message matches valid SIP formats
            if (
                sipMessage.startsWith('REGISTER') ||
                sipMessage.startsWith('UNREGISTER') ||
                sipMessage.startsWith('SIP/2.0')
            ) {
                return sipMessage;
            }
        }
        return null;
    } catch (error) {
        console.error('Error extracting SIP message:', error);
        throw error;
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
    // Split the message into lines, trim whitespace, and remove empty lines
    const lines = sipMessage.split(/\r?\n/).filter(line => line.trim() !== '');
    // Format each line with its index
    return lines.map((line, index) => `${index + 1}: ${line}`).join('\n');
}





}
