import pcap from "pcap";

export class PacketCaptureModule {
    private session: pcap.PcapSession;

    constructor(
        private networkInterface: string,
        filter: string = "port 5060"
    ) {
        try {
            this.session = pcap.createSession(networkInterface, { filter });
            console.log(`Listening on ${this.networkInterface} with filter '${filter}'...`);
        } catch (error) {
            console.error("Failed to create pcap session");
            process.exit(1);
        }
    }

    start() {
        if (typeof this.session.on !== 'function') {
            console.error("Session 'on' method not available");
            return;
        }

        this.session.on("packet", this.handlePacket.bind(this));
    }

    private handlePacket(rawPacket: Buffer) {
        console.log("Raw packet captured:", rawPacket);
        try {
            const packet = pcap.decode(rawPacket);
            console.log("Decoded packet:", packet);
        } catch (error) {
            console.error("Failed to decode packet:", error);
        }
    }

    stop() {
        try {
            this.session.close();
            console.log("Packet capture session stopped.");
        } catch (error) {
            console.error("Failed to close session", error);
            throw new Error("Failed to close session");
        }
    }
}
