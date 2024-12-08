export function formatSIPMessage(sipMessage: string | null | undefined): string {
    if (!sipMessage) {
        return '';
    }
    const lines = sipMessage.split(/\r?\n/).filter(line => line.trim() !== '');
    return lines.map((line, index) => `${index + 1}: ${line}`).join('\n');
}
