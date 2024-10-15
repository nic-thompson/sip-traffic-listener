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
                const decoded = pcap.decode(rawPacket);
                console.log('Decoded packet:', decoded);
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
