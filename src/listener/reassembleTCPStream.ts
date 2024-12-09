export function reassembleTCPStream(
    packet: any,
    tcpStreams: Map<string, Buffer>
): string | null {
    const src = packet.payload?.saddr;
    const dst = packet.payload?.daddr;
    const sport = packet.payload?.payload?.sport;
    const dport = packet.payload?.payload?.dport;

    if (!src || !dst || !sport || !dport || !packet.payload?.payload?.payload) {
        return null;
    }

    const streamKey = `${src}:${sport}-${dst}:${dport}`;
    const tcpPayload = packet.payload.payload.payload;

    const currentBuffer = tcpStreams.get(streamKey) || Buffer.alloc(0);
    const updatedBuffer = Buffer.concat([currentBuffer, tcpPayload]);

    const message = updatedBuffer.toString('utf-8');

    if (message.includes('\r\n\r\n')) {
        const headersEndIndex = message.indexOf('\r\n\r\n');
        const headers = message.substring(0, headersEndIndex);
        const contentLengthMatch = headers.match(/Content-Length:\s*(\d+)/i);

        if (contentLengthMatch) {
            const contentLength = parseInt(contentLengthMatch[1], 10);
            const bodyStartIndex = headersEndIndex + 4;
            const body = message.substring(bodyStartIndex);

            if (body.length >= contentLength) {
                tcpStreams.delete(streamKey);
                return message;
            }
        } else {
            tcpStreams.delete(streamKey);
            return message.substring(0, headersEndIndex + 4);
        }
    }

    tcpStreams.set(streamKey, updatedBuffer);
    return null;
}
