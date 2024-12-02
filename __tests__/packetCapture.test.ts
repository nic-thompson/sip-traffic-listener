import pcap from 'pcap';
import { PacketCaptureModule } from '../src/listener/packetCapture';
import { extractSIPMessage } from '../src/listener/extractSIPMessage';
import chalk from 'chalk';

// Mock the chalk module
jest.mock('chalk', () => ({
    blue: (text: string) => text,
    yellow: (text: string) => text,
    green: (text: string) => text,
    red: (text: string) => text,
}));

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
                        protocol: 17, // UDP protocol
                    },
                };
                callback(testPacket);
            }
        }),
        close: jest.fn(),
    })),
    decode: jest.fn(packet => ({
        payload: packet.payload, // Match the nested payload structure
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
    
        const mockSession = (pcap.createSession as jest.Mock).mock.results[0].value;
        const nonTcpPacket = {
            payload: {
                protocol: 17, // UDP
                payload: {
                    payload: {
                        data: Buffer.from('REGISTER sip:example.com SIP/2.0'),
                    },
                },
            },
        };
    
        mockSession.on.mock.calls[0][1](nonTcpPacket);
    
        expect(console.log).toHaveBeenCalledWith(chalk.blue('Raw packet captured.'));
        expect(console.log).toHaveBeenCalledWith(
            chalk.green('Extracted SIP Message:'),
            'REGISTER sip:example.com SIP/2.0'
        );
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
        const sipPacket = {
            payload: {
                protocol: 17, // UDP
                payload: {
                    payload: {
                        data: Buffer.from('REGISTER sip:example.com SIP/2.0')
                    }
                }
            }
        };
    
        mockSession.on.mock.calls[0][1](sipPacket);
    
        expect(console.log).toHaveBeenCalledWith('Raw packet captured.');
        expect(console.log).toHaveBeenCalledWith('Extracted SIP Message:', 'REGISTER sip:example.com SIP/2.0');
    });

    it('should log a warning when no SIP message is found in a packet', () => {
        jest.spyOn(console, 'warn').mockImplementation(() => {});
    
        const packetCapture = new PacketCaptureModule('eth2');
        packetCapture.start();
    
        const mockSession = (pcap.createSession as jest.Mock).mock.results[0].value;
    
        // Simulate a packet that does not contain SIP message
        const nonSipPacket = {
            payload: {
                payload: {
                    payload: {
                        data: Buffer.from('INVALID DATA'), // Clearly non-SIP
                    },
                },
            },
        };
    
        mockSession.on.mock.calls[0][1](nonSipPacket);
    
        // Verify the warning is logged
        expect(console.warn).toHaveBeenCalledWith('No SIP message found in the packet.');
    });
    
    it('should log the complete SIP message when reassembly is successful', () => {
        jest.spyOn(console, 'log').mockImplementation(() => {});
        const packetCapture = new PacketCaptureModule('eth2');
        packetCapture.start();
    
        const mockSession = (pcap.createSession as jest.Mock).mock.results[0].value;
    
        // Simulate a TCP packet that can be reassembled into a SIP message
        const tcpPacket = {
            payload: {
                protocol: 6, // TCP protocol
                payload: {
                    segments: [
                        Buffer.from('REGISTER sip:'),
                        Buffer.from('example.com SIP/2.0'),
                    ],
                },
            },
        };
    
        // Mock the `reassembleTCPStream` method to produce a complete SIP message
        jest.spyOn(packetCapture, 'reassembleTCPStream').mockReturnValue('REGISTER sip:example.com SIP/2.0');
    
        // Trigger the packet handler with the mocked TCP packet
        mockSession.on.mock.calls[0][1](tcpPacket);
    
        // Verify logs
        expect(console.log).toHaveBeenCalledWith('Raw packet captured.');
        expect(console.log).toHaveBeenCalledWith('Complete SIP Message:', 'REGISTER sip:example.com SIP/2.0');
    });
    
    it('should log an error when extractSIPMessage throws an exception', () => {
        jest.spyOn(console, 'error').mockImplementation(() => {});
        const packetCapture = new PacketCaptureModule('eth2');
        packetCapture.start();
    
        const mockSession = (pcap.createSession as jest.Mock).mock.results[0].value;
        const faultyPacket = {
            payload: {
                protocol: 17, // UDP
                payload: {
                    payload: {
                        data: {
                            toString: () => {
                                throw new Error('Forced error'); // Force an exception
                            }
                        }
                    }
                }
            }
        };
    
        mockSession.on.mock.calls[0][1](faultyPacket);
    
        expect(console.error).toHaveBeenCalledWith(
            'Error extracting SIP message:',
            expect.any(Error)
        );
    });

    it('should handle a packet with completely missing data gracefully', () => {
        const emptyPacket = {};
    
        const result = extractSIPMessage(emptyPacket);
    
        expect(result).toBeNull();
    });
    
    it('should handle a SIP message with headers only and remove the stream key', () => {
        const packetCapture = new PacketCaptureModule('eth2');
    
        // Define stream key and headers-only message
        const streamKey = '192.168.1.1:5060-192.168.1.2:5060';
        const sipHeaders = `REGISTER sip:example.com SIP/2.0\r\nCSeq: 1 REGISTER\r\n\r\n`;
        packetCapture['tcpStreams'] = new Map([[streamKey, Buffer.from(sipHeaders)]]);
    
        // Simulate the packet
        const packet = {
            payload: {
                saddr: '192.168.1.1',
                daddr: '192.168.1.2',
                payload: {
                    sport: 5060,
                    dport: 5060,
                    payload: Buffer.from(''), // No additional payload
                },
            },
        };
    
        // Call the function
        const result = packetCapture.reassembleTCPStream(packet);
    
        // Assert the result is the complete SIP message
        expect(result).toBe(sipHeaders);
    
        // Assert the stream key has been removed from the buffer
        expect(packetCapture['tcpStreams'].has(streamKey)).toBe(false);
    });  

    it('should format a SIP message into a more readable form', () => {
        const packetCapture = new PacketCaptureModule('eth2');
        const sipMessage = `REGISTER sip:example.com SIP/2.0\r\n` +
                           `Via: SIP/2.0/UDP 192.168.1.1;branch=z9hG4bK-776asdhds\r\n` +
                           `Content-Length: 0\r\n\r\n`;
        
        const expectedMessage = 
            `1: REGISTER sip:example.com SIP/2.0\n` +
            `2: Via: SIP/2.0/UDP 192.168.1.1;branch=z9hG4bK-776asdhds\n` +
            `3: Content-Length: 0`;
    
        const formattedMessage = packetCapture.formatSIPMessage(sipMessage);
    
        console.log('Expected Message:\n', expectedMessage);
        console.log('Formatted Message:\n', formattedMessage);
    
        expect(formattedMessage).toBe(expectedMessage);
    });

    it('should return an empty string if SIP message is null or undefined', () => {
        const packetCapture = new PacketCaptureModule('eth2');
    
        // Call formatSIPMessage with null
        const resultNull = packetCapture.formatSIPMessage(null);
        expect(resultNull).toBe('');
    
        // Call formatSIPMessage with undefined
        const resultUndefined = packetCapture.formatSIPMessage(undefined);
        expect(resultUndefined).toBe('');
    });
    
});

describe('reassembleTCPStream', () => {
    it('should reassemble fragmented TCP packets into a complete SIP message', () => {
        const packetCapture = new PacketCaptureModule('eth2');

        const mockPacketPart1 = {
            payload: {
                saddr: '192.168.1.1',
                daddr: '192.168.1.2',
                payload: {
                    sport: 5060,
                    dport: 5060,
                    payload: Buffer.from('REGISTER sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP ')
                }
            }
        };

        const mockPacketPart2 = {
            payload: {
                saddr: '192.168.1.1',
                daddr: '192.168.1.2',
                payload: {
                    sport: 5060,
                    dport: 5060,
                    payload: Buffer.from('192.168.1.1;branch=z9hG4bK-776asdhds\r\nContent-Length: 0\r\n\r\n')
                }
            }
        };

        // Pass the first packet part
        const resultPart1 = packetCapture['reassembleTCPStream'](mockPacketPart1);
        expect(resultPart1).toBeNull(); // Not complete yet

        // Pass the second packet part
        const resultPart2 = packetCapture['reassembleTCPStream'](mockPacketPart2);
        expect(resultPart2).toBe(
            'REGISTER sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.1;branch=z9hG4bK-776asdhds\r\nContent-Length: 0\r\n\r\n'
        ); // Complete message
    });

    it('should handle a single complete TCP packet', () => {
        const packetCapture = new PacketCaptureModule('eth2');

        const mockCompletePacket = {
            payload: {
                saddr: '192.168.1.1',
                daddr: '192.168.1.2',
                payload: {
                    sport: 5060,
                    dport: 5060,
                    payload: Buffer.from(
                        'REGISTER sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.1;branch=z9hG4bK-776asdhds\r\nContent-Length: 0\r\n\r\n'
                    )
                }
            }
        };

        const result = packetCapture['reassembleTCPStream'](mockCompletePacket);
        expect(result).toBe(
            'REGISTER sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.1;branch=z9hG4bK-776asdhds\r\nContent-Length: 0\r\n\r\n'
        );
    });

    it('should reset the buffer after reassembly', () => {
        const packetCapture = new PacketCaptureModule('eth2');

        const mockPacketPart1 = {
            payload: {
                saddr: '192.168.1.1',
                daddr: '192.168.1.2',
                payload: {
                    sport: 5060,
                    dport: 5060,
                    payload: Buffer.from('REGISTER sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP ')
                }
            }
        };

        const mockPacketPart2 = {
            payload: {
                saddr: '192.168.1.1',
                daddr: '192.168.1.2',
                payload: {
                    sport: 5060,
                    dport: 5060,
                    payload: Buffer.from('192.168.1.1;branch=z9hG4bK-776asdhds\r\nContent-Length: 0\r\n\r\n')
                }
            }
        };

        // Reassemble the packets
        packetCapture['reassembleTCPStream'](mockPacketPart1);
        const result = packetCapture['reassembleTCPStream'](mockPacketPart2);

        // Verify the buffer is cleared after reassembly
        expect(result).toBe(
            'REGISTER sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.1;branch=z9hG4bK-776asdhds\r\nContent-Length: 0\r\n\r\n'
        );

        // Verify the buffer is reset
        const streamKey = '192.168.1.1:5060-192.168.1.2:5060';
        expect(packetCapture['tcpStreams'].has(streamKey)).toBe(false);
    });

    it('should handle errors during TCP stream reassembly gracefully', () => {
        const packetCapture = new PacketCaptureModule('eth2');
    
        const faultyTcpPacket = {
            payload: {
                protocol: 6, // TCP
                payload: {
                    segments: null, // Simulate malformed TCP data
                },
            },
        };
    
        const result = packetCapture.reassembleTCPStream(faultyTcpPacket);
    
        expect(result).toBe(null);
    });

    it('should return null for malformed TCP packet in reassembleTCPStream', () => {
        const packetCapture = new PacketCaptureModule('eth2');
    
        const malformedTcpPacket = {
            payload: {
                protocol: 6, // TCP protocol
                payload: null, // No TCP data present
            },
        };
    
        const result = packetCapture.reassembleTCPStream(malformedTcpPacket);
    
        // Expect null to be returned for malformed TCP packets
        expect(result).toBeNull();
    });
});