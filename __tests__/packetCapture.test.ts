import pcap from "pcap";
import { PacketCaptureModule } from "../src/interceptor/packetCapture";

jest.mock("pcap", () => {
    return {
        createSession: jest.fn(() => ({
            on: jest.fn((event, callback) => {
                if (event === 'packet') {
                    const fakePacket = Buffer.from([0x00, 0x01, 0x02]);
                    callback(fakePacket);
                }
            }),
            close: jest.fn(),
        })),
        decode: jest.fn(() => ({
            data: "fake decoded packet data",
        })),
    };
});

describe("PacketCaptureModule", () => {
    let mockExit: jest.SpyInstance;

    beforeEach(() => {
        jest.spyOn(console, "log").mockImplementation(() => {});
        jest.spyOn(console, "error").mockImplementation(() => {});
        mockExit = jest.spyOn(process, "exit").mockImplementation((code?: string | number | null | undefined): never => {
            throw new Error(`process.exit called with ${code}`);
        });
    });

    afterEach(() => {
        jest.clearAllMocks();
        mockExit.mockRestore();
    });

    it("should create a pcap session with the correct interface and filter", () => {
        const networkInterface = "eth2";
        const filter = "tcp port 5060";
        const packetCapture = new PacketCaptureModule(networkInterface, filter);

        expect(packetCapture).toBeDefined();
    });

    it("should log a message when a packet is captured", () => {
        const networkInterface = "eth2";
        const filter = "tcp port 5060";
        const packetCapture = new PacketCaptureModule(networkInterface, filter);

        packetCapture.start();

        expect(console.log).toHaveBeenCalledWith("Raw packet captured:", expect.any(Buffer));
        expect(console.log).toHaveBeenCalledWith("Decoded packet:", expect.any(Object));
    });

    it("should log an error and exit when pcap session creation fails", () => {
        (pcap.createSession as jest.Mock).mockImplementationOnce(() => {
            throw new Error("Failed to create session");
        });

        expect(() => {
            new PacketCaptureModule("eth2");
        }).toThrowError("process.exit called with 1");

        expect(console.error).toHaveBeenCalledWith("Failed to create pcap session");
        expect(mockExit).toHaveBeenCalledWith(1);
    });

    it("should close the pcap session when stop is called without throwing an error", () => {
        const packetCapture = new PacketCaptureModule("eth2");
        const mockSession = (pcap.createSession as jest.Mock).mock.results[0].value;

        expect(() => packetCapture.stop()).not.toThrow(); 
        expect(mockSession.close).toHaveBeenCalled();
        expect(console.log).toHaveBeenCalledWith("Packet capture session stopped.");
    });

    it("should log an error when packet decoding fails", () => {
        (pcap.decode as jest.Mock).mockImplementationOnce(() => {
            throw new Error("Failed to decode packet");
        });

        const packetCapture = new PacketCaptureModule("eth2");
        packetCapture.start();

        expect(console.error).toHaveBeenCalledWith("Failed to decode packet:", expect.any(Error));
    });

    it("should handle the case where session.on is not a function", () => {
        const mockSession = {
            on: undefined,
            close: jest.fn(),
        };
        (pcap.createSession as jest.Mock).mockReturnValueOnce(mockSession);

        const packetCapture = new PacketCaptureModule("eth2");

        expect(() => packetCapture.start()).not.toThrow();
        expect(console.error).toHaveBeenCalledWith("Session 'on' method not available");
    });

    it("should log an error if session.close fails", () => {
        const packetCapture = new PacketCaptureModule("eth2");
        const mockSession = (pcap.createSession as jest.Mock).mock.results[0].value;

        mockSession.close = jest.fn(() => {
            throw new Error("Close failed");
        });

        expect(() => packetCapture.stop()).toThrow("Failed to close session");
        expect(console.error).toHaveBeenCalledWith("Failed to close session", expect.any(Error));
    });
});
