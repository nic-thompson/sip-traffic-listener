import pcap from 'pcap';
import { PacketCaptureModule } from '../src/interceptor/packetCapture';

jest.mock('pcap', () => ({
    createSession: jest.fn(() => ({
        on: jest.fn((event, callback) => {
            if (event === 'packet') {
                // Simulated raw packet
                const testPacket = {
                    payload: {
                        payload: {
                            payload: {
                                data: Buffer.from('REGISTER sip:example.com SIP/2.0'),
                            },
                        },
                    },
                };
                callback(testPacket);
            }
        }),
        close: jest.fn(),
    })),
    decode: jest.fn(packet => ({
        data: 'fake decoded packet data',
        payload: packet.payload, // Use payload from the mocked packet
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
        jest.spyOn(console, 'warn').mockImplementation(() => {});
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
                        data: expect.any(Buffer), // Match the actual type
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
    
    it('should extract a SIP message from a packet', () => {
        const packetCapture = new PacketCaptureModule('eth2');
        packetCapture.start();

        const mockSession = (pcap.createSession as jest.Mock).mock.results[0].value;
        const packetHandler = mockSession.on.mock.calls[0][1];

        // Simulate a packet with a SIP message
        const sipPacket = {
            payload: {
                payload: {
                    payload: {
                        data: Buffer.from('REGISTER sip:example.com SIP/2.0'),
                    },
                },
            },
        };

        packetHandler(sipPacket);

        expect(console.log).toHaveBeenCalledWith('Raw packet captured.');
        expect(console.log).toHaveBeenCalledWith('Extracted SIP Message:', 'REGISTER sip:example.com SIP/2.0');
    });

    it('should log a warning when no SIP message is found in a packet', () => {
        jest.spyOn(console, 'log').mockImplementation(() => {});
        jest.spyOn(console, 'warn').mockImplementation(() => {});
    
        const packetCapture = new PacketCaptureModule('eth2');
        packetCapture.start();
    
        const mockSession = (pcap.createSession as jest.Mock).mock.results[0].value;
    
        // Debug: Verify handler calls
        console.log('Mock session calls:', mockSession.on.mock.calls);
        // process.stdout.write(`Mock session calls: ${JSON.stringify(mockSession.on.mock.calls)}\n`);
    
        // Properly define the test packet
        const nonSipPacket = {
            payload: {
                payload: {
                    payload: {
                        data: Buffer.from('GET / HTTP/1.1'), // Non-SIP data
                    },
                },
            },
        };
    
        // Debug: Verify packet structure
        console.log('Test packet:', nonSipPacket);
        // process.stdout.write(`Test packet structure: ${JSON.stringify(nonSipPacket)}\n`);
    
        // Trigger the packet handler
        mockSession.on.mock.calls[0][1](nonSipPacket);
    
        // Verify logs
        expect(console.log).toHaveBeenCalledWith('Raw packet captured.');
        expect(console.warn).toHaveBeenCalledWith('No SIP message found in the packet.');
    });  

    it('should log an error when extractSIPMessage throws an exception', () => {
        jest.spyOn(console, 'error').mockImplementation(() => {});
        const packetCapture = new PacketCaptureModule('eth2');
        packetCapture.start();
    
        const mockSession = (pcap.createSession as jest.Mock).mock.results[0].value;
    
        // Simulate a packet with a structure that causes an exception
        const faultyPacket = {
            payload: {
                payload: {
                    payload: {
                        data: {
                            toString: () => {
                                throw new Error('Forced error'); // Force an exception
                            },
                        },
                    },
                },
            },
        };
    
        // Trigger the packet handler with the faulty packet
        mockSession.on.mock.calls[0][1](faultyPacket);
    
        // Verify the error log
        expect(console.error).toHaveBeenCalledWith(
            'Error extracting SIP message:',
            expect.any(Error)
        );
    });
});
