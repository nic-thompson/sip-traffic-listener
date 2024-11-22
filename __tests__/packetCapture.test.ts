import pcap from 'pcap';
import { PacketCaptureModule } from '../src/interceptor/packetCapture';

jest.mock('pcap', () => ({
    createSession: jest.fn(() => ({
        on: jest.fn((event, callback) => {
            if (event === 'packet') {
                const fakePacket = Buffer.from('REGISTER sip:example.com SIP/2.0');
                callback(fakePacket);
            }
        }),
        close: jest.fn(),
    })),
    decode: jest.fn(() => ({
        data: 'fake decoded packet data',
        payload: {
            payload: {
                payload: {
                    data: Buffer.from('REGISTER sip:example.com SIP/2.0'),
                },
            },
        },
    })),
}));

describe('PacketCaptureModule', () => {
    let mockExit: jest.SpyInstance;

    beforeEach(() => {
        jest.spyOn(console, 'log').mockImplementation(() => {});
        jest.spyOn(console, 'error').mockImplementation(() => {});
        mockExit = jest.spyOn(process, 'exit').mockImplementation((code?: string | number | null | undefined): never => {
            throw new Error(`process.exit called with ${code}`);
        });
    });

    afterEach(() => {
        jest.clearAllMocks();
        mockExit.mockRestore();
    });

    it('should create a pcap session with the correct interface and filter', () => {
        const networkInterface = 'eth2';
        const filter = 'tcp port 5060';
        const packetCapture = new PacketCaptureModule(networkInterface, filter);

        expect(packetCapture).toBeDefined();
        expect(pcap.createSession).toHaveBeenCalledWith(networkInterface, { filter });
    });

    it('should log a message when a packet is captured', () => {
        const packetCapture = new PacketCaptureModule('eth2');
        packetCapture.start();

        expect(console.log).toHaveBeenCalledWith('Raw packet captured.');
        expect(console.log).toHaveBeenCalledWith('Decoded packet:', expect.objectContaining({
            data: 'fake decoded packet data',
            payload: expect.objectContaining({
                payload: expect.objectContaining({
                    payload: expect.objectContaining({
                        data: expect.any(Buffer),
                    }),
                }),
            }),
        }));
    });

    it('should log an error and exit when pcap session creation fails', () => {
        (pcap.createSession as jest.Mock).mockImplementationOnce(() => {
            throw new Error('Failed to create session');
        });

        expect(() => {
            new PacketCaptureModule('eth2');
        }).toThrowError('process.exit called with 1');

        expect(console.error).toHaveBeenCalledWith('Failed to create pcap session:', expect.any(Error));
        expect(mockExit).toHaveBeenCalledWith(1);
    });

    it('should handle the case when "session.on" is undefined', () => {
        (pcap.createSession as jest.Mock).mockReturnValueOnce({ on: undefined });

        const packetCapture = new PacketCaptureModule('eth2');
        packetCapture.start();

        expect(console.error).toHaveBeenCalledWith("Session 'on' method not available");
    });

    it('should log an error if packet decoding fails', () => {
        (pcap.decode as jest.Mock).mockImplementationOnce(() => {
            throw new Error('Decoding failed');
        });

        const packetCapture = new PacketCaptureModule('eth2');
        packetCapture.start();

        const mockSession = (pcap.createSession as jest.Mock).mock.results[0].value;
        const packetHandler = mockSession.on.mock.calls[0][1];
        packetHandler(Buffer.from('mock packet'));

        expect(console.error).toHaveBeenCalledWith('Failed to decode packet:', expect.any(Error));
    });

    it('should close the pcap session when stop is called without throwing an error', () => {
        const packetCapture = new PacketCaptureModule('eth2');
        const mockSession = (pcap.createSession as jest.Mock).mock.results[0].value;

        expect(() => packetCapture.stop()).not.toThrow();
        expect(mockSession.close).toHaveBeenCalled();
        expect(console.log).toHaveBeenCalledWith('Packet capture session stopped.');
    });

    it('should handle errors during session closure gracefully', () => {
        // Arrange: Create an instance of PacketCaptureModule to trigger `pcap.createSession`
        const packetCapture = new PacketCaptureModule('eth2');
    
        // Access the mocked session returned by `pcap.createSession`
        const mockSession = (pcap.createSession as jest.Mock).mock.results[0].value;
    
        // Simulate an error when `close` is called
        mockSession.close.mockImplementationOnce(() => {
            throw new Error('Close failed');
        });
    
        // Act & Assert: Call `stop` and ensure it throws an error
        expect(() => packetCapture.stop()).toThrow('Failed to close session');
        expect(console.error).toHaveBeenCalledWith('Failed to close session', expect.any(Error));
    });    
});
