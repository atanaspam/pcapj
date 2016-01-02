package uk.ac.gla.atanaspam.pcapj;

/**
 * This class represents a packet header.
 * @author atanaspam
 * @created 22/10/2015
 * @version 0.4
 */
public class PcapPacketHeader{

    public static final int pcapPacketHeaderSize = 16;
    public static final int capLenOffset = 8;

    public long timestamp;
    public long packetSize;

    @Override
    public String toString() {
        return "PcapPacketHeader{" +
                "timestamp=" + timestamp +
                ", packetSize=" + packetSize +
                '}';
    }
}
