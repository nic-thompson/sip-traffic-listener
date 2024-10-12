import pcap from 'pcap';

export class PacketCaptureModule {
    private session: pcap.PcapSession;

    constructor(private networkInterface: string, filter: string = 'port 5060') {
        try {
            this.session = pcap.createSession(networkInterface, { filter });
            console.log(`Listening on ${this.networkInterface} with filter '${filter}'...`);
        } catch (error) {
            console.error('Failed to create pcap session');
            process.exit(1);
        }
    }

    start() {
        this.session.on('packet', this.handlePacket);
    }

    private handlePacket() {
        console.log('Packet captured');
    }

    stop() {
        this.session.close();
        console.log('Packet capture session stopped.');
    }
}
