import { formatSIPMessage } from '../listener/formatSIPMessage';

describe('formatSIPMessage', () => {
    it('should return an empty string for null input', () => {
        const result = formatSIPMessage(null);
        expect(result).toBe('');
    });

    it('should return an empty string for undefined input', () => {
        const result = formatSIPMessage(undefined);
        expect(result).toBe('');
    });

    it('should return an empty string for an empty string input', () => {
        const result = formatSIPMessage('');
        expect(result).toBe('');
    });

    it('should format a valid SIP message into numbered lines', () => {
        const sipMessage = `REGISTER sip:example.com SIP/2.0\r\nContent-Length: 0\r\n`;
        const result = formatSIPMessage(sipMessage);
        expect(result).toBe('1: REGISTER sip:example.com SIP/2.0\n2: Content-Length: 0');
    });

    it('should ignore empty lines in a SIP message', () => {
        const sipMessage = `REGISTER sip:example.com SIP/2.0\r\n\r\nContent-Length: 0\r\n`;
        const result = formatSIPMessage(sipMessage);
        expect(result).toBe('1: REGISTER sip:example.com SIP/2.0\n2: Content-Length: 0');
    });
});
