import { PacketCaptureModule } from '../listener/packetCapture';
import { reassembleTCPStream } from '../listener/reassembleTCPStream';

jest.mock('../listener/reassembleTCPStream', () => ({
    reassembleTCPStream: jest.fn((packet, _tcpStreams) => {
        const sipMessage = packet.payload?.data?.toString('utf-8');
        return sipMessage ? `Processed: ${sipMessage}` : null;
    }),
}));

jest.mock('pcap', () => ({
    createSession: jest.fn(() => ({
        on: jest.fn((event, callback) => {
            if (event === 'packet') {
                setImmediate(() => callback(Buffer.from('REGISTER sip:example.com SIP/2.0')));
                setImmediate(() => callback(Buffer.from('SIP/2.0 200 OK')));
            }
        }),
        close: jest.fn(),
    })),
    decode: jest.fn((rawPacket) => {
        return {
            payload: {
                protocol: 6, // Simulate TCP protocol
                data: rawPacket, // Flat data structure
            },
        };
    }),
}));

const mockedReassembleTCPStream = reassembleTCPStream as jest.Mock;

describe('Asynchronous SIP Processing', () => {
    let packetCapture: PacketCaptureModule;
    let consoleLogSpy: jest.SpyInstance;

    beforeEach(() => {
        jest.clearAllMocks();
        consoleLogSpy = jest.spyOn(console, 'log').mockImplementation(() => {}); // Mock console.log
        packetCapture = new PacketCaptureModule('eth2');
    });

    afterEach(() => {
        consoleLogSpy.mockRestore(); // Restore console.log after tests
    });

    it('should process multiple SIP messages asynchronously', async () => {
        packetCapture.start();

        // Wait for asynchronous processing to complete
        await new Promise((resolve) => setTimeout(resolve, 1000));

        expect(mockedReassembleTCPStream).toHaveBeenCalledTimes(2);
    });
});

