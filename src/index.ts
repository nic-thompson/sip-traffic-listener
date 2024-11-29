import { PacketCaptureModule } from '../src/listener/packetCapture';

const networkInterface = 'eth2';
const filter = 'udp port 5060 or tcp port 5060';

try {
    const packetCapture = new PacketCaptureModule(networkInterface, filter);
    console.log(
        `Starting packet capture on ${networkInterface} with filter ${filter}`
    );
    packetCapture.start();
} catch (error) {
    if (error instanceof Error) {
        console.error(`Failed to start packet capture: ${error.message}`);
    } else {
        console.error(`Failed to start packet capture: Unknown error`);
    }
}
