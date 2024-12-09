import pcap from 'pcap';
import { PacketCaptureModule } from '../listener/packetCapture';
import { formatSIPMessage } from '../listener/formatSIPMessage';
import { reassembleTCPStream } from '../listener/reassembleTCPStream';

jest.mock('pcap', () => ({
    createSession: jest.fn(() => ({
        on: jest.fn((event, callback) => {
            if (event === 'packet') {
                const testPacket = {
                    payload: {
                        payload: {
                            payload: {
                                data: Buffer.from('REGISTER sip:example.com SIP/2.0'),
                            },
                        },
                        protocol: 17, // UDP protocol
                    },
                };
                callback(testPacket);
            }
        }),
        close: jest.fn(),
    })),
    decode: jest.fn((packet) => ({
        payload: packet.payload, // Match the nested payload structure
    })),
}));

jest.mock('../listener/reassembleTCPStream', () => ({
    reassembleTCPStream: jest.fn(),
}));

describe('PacketCaptureModule', () => {
    let mockExit: jest.SpyInstance;

    beforeEach(() => {
        jest.spyOn(console, 'log').mockImplementation(() => {});
        jest.spyOn(console, 'error').mockImplementation(() => {});
        mockExit = jest.spyOn(process, 'exit').mockImplementation(() => {
            throw new Error('process.exit called');
        });
        jest.spyOn(console, 'warn').mockImplementation(() => {});
    });

    afterEach(() => {
        jest.clearAllMocks();
        mockExit.mockRestore();
    });

    it('should format a valid SIP message', () => {
        const sipMessage = 'REGISTER sip:example.com SIP/2.0\r\nContent-Length: 0\r\n';
        const formattedMessage = formatSIPMessage(sipMessage);
        expect(formattedMessage).toBe('1: REGISTER sip:example.com SIP/2.0\n2: Content-Length: 0');
    });

    it('should log the complete SIP message when reassembly is successful', () => {
        jest.spyOn(console, 'log').mockImplementation(() => {});
        (reassembleTCPStream as jest.Mock).mockReturnValueOnce('mockedMessage');
        
        const packetCapture = new PacketCaptureModule('eth2');
        packetCapture.start();

        const mockSession = (pcap.createSession as jest.Mock).mock.results[0].value;

        const tcpPacket = {
            payload: {
                protocol: 6, // TCP protocol
                payload: {
                    sport: 5060,
                    dport: 5060,
                    payload: Buffer.from('REGISTER sip:example.com SIP/2.0\r\n'),
                },
            },
        };

        mockSession.on.mock.calls[0][1](tcpPacket);

        expect(reassembleTCPStream).toHaveBeenCalledWith(tcpPacket, expect.any(Map));
        expect(console.log).toHaveBeenCalledWith('Complete SIP Message:', 'mockedMessage');
    });

    it('should handle errors during TCP stream reassembly gracefully', () => {
        const tcpStreams = new Map<string, Buffer>();
        (reassembleTCPStream as jest.Mock).mockImplementationOnce(() => null);

        const faultyTcpPacket = {
            payload: {
                protocol: 6, // TCP
                payload: {
                    sport: 5060,
                    dport: 5060,
                    payload: null, // Simulate malformed TCP data
                },
            },
        };

        const result = reassembleTCPStream(faultyTcpPacket, tcpStreams);
        expect(result).toBe(null);
    });

    it('should handle fragmented TCP packets', () => {
        jest.unmock('../listener/reassembleTCPStream');
        const { reassembleTCPStream } = require('../listener/reassembleTCPStream');

        const tcpStreams = new Map<string, Buffer>();

        const mockPacketPart1 = {
            payload: {
                saddr: '192.168.1.1',
                daddr: '192.168.1.2',
                payload: {
                    sport: 5060,
                    dport: 5060,
                    payload: Buffer.from('REGISTER sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP '),
                },
            },
        };

        const mockPacketPart2 = {
            payload: {
                saddr: '192.168.1.1',
                daddr: '192.168.1.2',
                payload: {
                    sport: 5060,
                    dport: 5060,
                    payload: Buffer.from(
                        '192.168.1.1;branch=z9hG4bK-776asdhds\r\n\r\n'
                    ),
                },
            },
        };

        // Pass the first packet part
        const result1 = reassembleTCPStream(mockPacketPart1, tcpStreams);
        expect(result1).toBeNull();

        // Pass the second packet part
        const result2 = reassembleTCPStream(mockPacketPart2, tcpStreams);
        expect(result2).toBe(
            'REGISTER sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.1;branch=z9hG4bK-776asdhds\r\n\r\n'
        );
    });

    it('should reset the buffer after reassembly', () => {
        const tcpStreams = new Map<string, Buffer>();

        const mockPacketPart1 = {
            payload: {
                saddr: '192.168.1.1',
                daddr: '192.168.1.2',
                payload: {
                    sport: 5060,
                    dport: 5060,
                    payload: Buffer.from('REGISTER sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP '),
                },
            },
        };

        const mockPacketPart2 = {
            payload: {
                saddr: '192.168.1.1',
                daddr: '192.168.1.2',
                payload: {
                    sport: 5060,
                    dport: 5060,
                    payload: Buffer.from('192.168.1.1;branch=z9hG4bK-776asdhds\r\n\r\n'),
                },
            },
        };

        reassembleTCPStream(mockPacketPart1, tcpStreams);
        reassembleTCPStream(mockPacketPart2, tcpStreams);

        const streamKey = '192.168.1.1:5060-192.168.1.2:5060';
        expect(tcpStreams.has(streamKey)).toBe(false);
    });

    it('should log an error and exit when pcap session creation fails', () => {
        (pcap.createSession as jest.Mock).mockImplementationOnce(() => {
            throw new Error('Simulated session creation failure');
        });
    
        const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => {
            throw new Error('process.exit called');
        });
    
        expect(() => {
            new PacketCaptureModule('eth2');
        }).toThrowError('process.exit called');
    
        expect(console.error).toHaveBeenCalledWith(
            'Failed to create pcap session:',
            expect.any(Error)
        );
        expect(mockExit).toHaveBeenCalledWith(1);
    
        mockExit.mockRestore();
    });

    it('should log an error and return when the session "on" method is unavailable', () => {
        (pcap.createSession as jest.Mock).mockReturnValueOnce({
            on: undefined, // Simulate missing 'on' method
        });
    
        const packetCapture = new PacketCaptureModule('eth2');
    
        packetCapture.start();
    
        expect(console.error).toHaveBeenCalledWith("Session 'on' method not available");
    });

    it('should log a warning when no SIP message is found in a packet', () => {
        jest.spyOn(console, 'warn').mockImplementation(() => {});
        const packetCapture = new PacketCaptureModule('eth2');
        packetCapture.start();
    
        const mockSession = (pcap.createSession as jest.Mock).mock.results[0].value;
    
        // Simulate a packet that does not contain a SIP message
        const nonSipPacket = {
            payload: {
                protocol: 17, // UDP
                payload: {
                    payload: {
                        data: Buffer.from('NON-SIP-DATA'), // Clearly non-SIP
                    },
                },
            },
        };
    
        mockSession.on.mock.calls[0][1](nonSipPacket);
    
        expect(console.warn).toHaveBeenCalledWith('No SIP message found in the packet.');
    });
    
    it('should log an error if packet decoding fails', () => {
        jest.spyOn(console, 'error').mockImplementation(() => {});
        (pcap.decode as jest.Mock).mockImplementationOnce(() => {
            throw new Error('Decoding failed');
        });
    
        const packetCapture = new PacketCaptureModule('eth2');
        packetCapture.start();
    
        const mockSession = (pcap.createSession as jest.Mock).mock.results[0].value;
        mockSession.on.mock.calls[0][1](Buffer.from('mock packet'));
    
        expect(console.error).toHaveBeenCalledWith('Failed to decode packet:', expect.any(Error));
    });
    
    it('should close the session without errors when stop is called', () => {
        const packetCapture = new PacketCaptureModule('eth2');
        const mockSession = (pcap.createSession as jest.Mock).mock.results[0].value;
    
        expect(() => packetCapture.stop()).not.toThrow();
        expect(mockSession.close).toHaveBeenCalled();
        expect(console.log).toHaveBeenCalledWith('Packet capture session stopped.');
    });

    it('should log an error and throw when session closure fails', () => {
        jest.spyOn(console, 'error').mockImplementation(() => {});
        const packetCapture = new PacketCaptureModule('eth2');
    
        const mockSession = (pcap.createSession as jest.Mock).mock.results[0].value;
        mockSession.close.mockImplementationOnce(() => {
            throw new Error('Close failed');
        });
    
        expect(() => packetCapture.stop()).toThrow('Failed to close session');
        expect(console.error).toHaveBeenCalledWith('Failed to close session', expect.any(Error));
    });
    
    
});
