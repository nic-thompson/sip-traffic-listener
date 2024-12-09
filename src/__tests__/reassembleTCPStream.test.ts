import { reassembleTCPStream } from '../listener/reassembleTCPStream';

describe('reassembleTCPStream', () => {
    let tcpStreams: Map<string, Buffer>;

    beforeEach(() => {
        tcpStreams = new Map<string, Buffer>();
    });

    it('should return null when the packet is missing required data', () => {
        const malformedPacket = {
            payload: {
                saddr: '192.168.1.1',
                daddr: '192.168.1.2',
                payload: null, // No TCP data
            },
        };

        const result = reassembleTCPStream(malformedPacket, tcpStreams);
        expect(result).toBeNull();
    });

    it('should reassemble fragmented TCP packets into a complete SIP message', () => {
        const mockPacketPart1 = {
            payload: {
                saddr: '192.168.1.1',
                daddr: '192.168.1.2',
                payload: {
                    sport: 5060,
                    dport: 5060,
                    payload: Buffer.from(
                        'REGISTER sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP '
                    ),
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
                        '192.168.1.1;branch=z9hG4bK-776asdhds\r\nContent-Length: 0\r\n\r\n'
                    ),
                },
            },
        };

        const resultPart1 = reassembleTCPStream(mockPacketPart1, tcpStreams);
        expect(resultPart1).toBeNull(); // Not complete yet

        const resultPart2 = reassembleTCPStream(mockPacketPart2, tcpStreams);
        expect(resultPart2).toBe(
            'REGISTER sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.1;branch=z9hG4bK-776asdhds\r\nContent-Length: 0\r\n\r\n'
        );
    });

    it('should return null for packets without payloads', () => {
        const packetWithoutPayload = {
            payload: {
                saddr: '192.168.1.1',
                daddr: '192.168.1.2',
                payload: null, // Missing payload
            },
        };

        const result = reassembleTCPStream(packetWithoutPayload, tcpStreams);
        expect(result).toBeNull();
    });

    it('should reset the buffer after reassembly', () => {
        const mockPacketPart1 = {
            payload: {
                saddr: '192.168.1.1',
                daddr: '192.168.1.2',
                payload: {
                    sport: 5060,
                    dport: 5060,
                    payload: Buffer.from(
                        'REGISTER sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP '
                    ),
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
                        '192.168.1.1;branch=z9hG4bK-776asdhds\r\nContent-Length: 0\r\n\r\n'
                    ),
                },
            },
        };

        reassembleTCPStream(mockPacketPart1, tcpStreams);
        const result = reassembleTCPStream(mockPacketPart2, tcpStreams);

        // Validate complete reassembly
        expect(result).toBe(
            'REGISTER sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.1;branch=z9hG4bK-776asdhds\r\nContent-Length: 0\r\n\r\n'
        );

        // Ensure buffer is cleared
        const streamKey = '192.168.1.1:5060-192.168.1.2:5060';
        expect(tcpStreams.has(streamKey)).toBe(false);
    });

    it('should return null for TCP packets without payloads', () => {
        const tcpPacketWithoutPayload = {
            payload: {
                saddr: '192.168.1.1',
                daddr: '192.168.1.2',
                payload: {
                    sport: 5060,
                    dport: 5060,
                    payload: null, // No TCP payload
                },
            },
        };

        const result = reassembleTCPStream(tcpPacketWithoutPayload, tcpStreams);
        expect(result).toBeNull();
    });

    it('should return null for malformed packets', () => {
        const malformedPacket = {
            payload: {
                saddr: '192.168.1.1',
                daddr: null, // Missing destination address
                payload: {
                    sport: 5060,
                    dport: 5060,
                    payload: Buffer.from('Invalid data'),
                },
            },
        };

        const result = reassembleTCPStream(malformedPacket, tcpStreams);
        expect(result).toBeNull();
    });

    it('should handle packets with headers only and remove the stream key', () => {
        const streamKey = '192.168.1.1:5060-192.168.1.2:5060';
        const sipHeaders = `REGISTER sip:example.com SIP/2.0\r\nCSeq: 1 REGISTER\r\n\r\n`;
        tcpStreams.set(streamKey, Buffer.from(sipHeaders));

        const mockPacket = {
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

        const result = reassembleTCPStream(mockPacket, tcpStreams);

        expect(result).toBe(sipHeaders);
        expect(tcpStreams.has(streamKey)).toBe(false);
    });
});
