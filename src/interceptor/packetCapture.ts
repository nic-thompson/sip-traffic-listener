import pcap from 'pcap';

export class PacketCaptureModule {
    private session: any;
    private networkInterface: string;
    private filter: string;

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

                // Log the decoded packet
                console.log('Decoded packet:', decodedPacket);

                // Extract the SIP message
                const sipMessage = this.extractSIPMessage(decodedPacket);
                if (sipMessage) {
                    console.log('Extracted SIP Message:', sipMessage);
                } else {
                    console.warn('No SIP message found in the packet.');
                }
            } catch (error) {
                console.error('Failed to decode packet:', error); // Adjusted log to match test expectation
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

    private extractSIPMessage(packet: any): string | null {
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
    
                console.log('Invalid SIP Message:', sipMessage); // Debugging
            }
    
            console.log('No SIP Message Found'); // Debugging
            return null; // Explicitly return null for invalid SIP messages
        } catch (error) {
            console.error('Error extracting SIP message:', error);
            return null;
        }
    }         
}
