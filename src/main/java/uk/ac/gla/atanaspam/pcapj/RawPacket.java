package main.java.uk.ac.gla.atanaspam.pcapj;

/**
 * @author atanaspam
 * @version 0.5
 * @created 24/10/2015
 */
public class RawPacket {

    private byte[] packet;

    private PcapPacketHeader header;

    public RawPacket(byte[] data, PcapPacketHeader header){
        this.packet = data;
        this. header = header;
    }

    public byte[] getPacket() {
        return packet;
    }

    public PcapPacketHeader getHeader() {
        return header;
    }
}
