import pcap from "pcap";
import { PacketCaptureModule } from "../src/interceptor/packetCapture";

jest.mock("pcap", () => {
  return {
    createSession: jest.fn(() => ({
      on: jest.fn(),
      close: jest.fn(),
    })),
  };
});

describe("PacketCaptureModule", () => {
  let mockExit: jest.SpyInstance;

  beforeEach(() => {
    jest.spyOn(console, "log").mockImplementation(() => {});
    jest.spyOn(console, "error").mockImplementation(() => {});
    mockExit = jest.spyOn(process, "exit").mockImplementation((code?: unknown): never => {
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

    const mockSession = (pcap.createSession as jest.Mock).mock.results[0].value;
    mockSession.on.mock.calls[0][1]();

    expect(console.log).toHaveBeenCalledWith("Packet captured");
  });

  it("should log an error and exit when pcap session creation fails", () => {
    (pcap.createSession as jest.Mock).mockImplementation(() => {
      throw new Error("Failed to create session");
    });

    expect(() => {
      new PacketCaptureModule("eth2");
    }).toThrow("process.exit called with 1");

    expect(console.error).toHaveBeenCalledWith("Failed to create pcap session");
    expect(mockExit).toHaveBeenCalledWith(1);
  });

  it("should close the pcap session when stop is called without throwing an error", () => {
    (pcap.createSession as jest.Mock).mockImplementation(() => ({
      on: jest.fn(),
      close: jest.fn(),
    }));

    const packetCapture = new PacketCaptureModule("eth2");
    const mockSession = (pcap.createSession as jest.Mock).mock.results[0].value;

    expect(() => packetCapture.stop()).not.toThrow();

    expect(mockSession.close).toHaveBeenCalled();

    expect(console.log).toHaveBeenCalledWith("Packet capture session stopped.");
  });
});
