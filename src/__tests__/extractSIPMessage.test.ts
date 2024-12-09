import { extractSIPMessage } from '../listener/extractSIPMessage';

describe('extractSIPMessage', () => {
    it('should extract a REGISTER SIP message from a valid packet', () => {
        const packet = {
            payload: {
                payload: {
                    payload: {
                        data: Buffer.from('REGISTER sip:example.com SIP/2.0\r\n'),
                    },
                },
            },
        };

        const result = extractSIPMessage(packet);
        expect(result).toBe('REGISTER sip:example.com SIP/2.0');
    });

    it('should extract a SIP/2.0 response message from a valid packet', () => {
        const packet = {
            payload: {
                payload: {
                    payload: {
                        data: Buffer.from('SIP/2.0 200 OK\r\n'),
                    },
                },
            },
        };

        const result = extractSIPMessage(packet);
        expect(result).toBe('SIP/2.0 200 OK');
    });

    it('should return null for non-SIP data', () => {
        const nonSIPPacket = {
            payload: {
                payload: {
                    payload: {
                        data: Buffer.from('INVALID DATA'),
                    },
                },
            },
        };

        const result = extractSIPMessage(nonSIPPacket);
        expect(result).toBeNull();
    });

    it('should return null for an empty packet', () => {
        const emptyPacket = {};
        const result = extractSIPMessage(emptyPacket);
        expect(result).toBeNull();
    });

    it('should return null if there is no payload', () => {
        const noPayloadPacket = {
            payload: null,
        };

        const result = extractSIPMessage(noPayloadPacket);
        expect(result).toBeNull();
    });

    it('should throw an error if the data accessor throws an exception', () => {
        jest.spyOn(console, 'error').mockImplementation(() => {}); // Suppress error log
    
        const faultyPacket = {
            payload: {
                payload: {
                    payload: {
                        data: {
                            toString: () => {
                                throw new Error('Simulated toString error'); // Simulate error
                            },
                        },
                    },
                },
            },
        };
    
        expect(() => extractSIPMessage(faultyPacket)).toThrow('Simulated toString error');
    
        expect(console.error).toHaveBeenCalledWith(
            'Error extracting SIP message:',
            expect.any(Error)
        );
    
        jest.restoreAllMocks(); // Restore original console.error after the test
    });
    
});
