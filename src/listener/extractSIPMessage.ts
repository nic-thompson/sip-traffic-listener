export function extractSIPMessage(packet: any): string | null {
    try {
        let payload = packet?.payload;
        while (payload && payload.payload) {
            payload = payload.payload;
        }

        if (payload?.data) {
            const sipMessage = payload.data.toString('utf-8').trim();

            if (
                sipMessage.startsWith('REGISTER') ||
                sipMessage.startsWith('UNREGISTER') ||
                sipMessage.startsWith('SIP/2.0')
            ) {
                return sipMessage;
            }
        }
        return null;
    } catch (error) {
        console.error('Error extracting SIP message:', error);
        throw error;
    }
}
