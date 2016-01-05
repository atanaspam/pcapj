package uk.ac.gla.atanaspam.pcapj;

import java.net.InetAddress;

/**
 * This class represents a UDP packet and stores all the data that we are interested in for a UDP packet
 * @author atanaspam
 * @version 0.3
 */
public class UDPPacket extends IPPacket{

    final int inUDPHeaderSrcPortOffset = 0;
    final int inUDPHeaderDstPortOffset = 2;

    protected int src_port;
    protected int dst_port;
    protected byte[] data;

    public int getSrc_port() {
        return src_port;
    }

    public int getDst_port() {
        return dst_port;
    }

    public byte[] getData() {
        return data;
    }

    /**
     * @deprecated
     * This constructor takes an IPPacket object(superclass) and constructs a UDP
     * instance of it copying all the data carried by the superclass.
     * @param packet An already generated packet
     */
    public UDPPacket(IPPacket packet){
	    super(packet.timestamp);
	
	    this.src_ip = packet.src_ip;
	    this.dst_ip = packet.dst_ip;
        this.sourceMacAddress = packet.sourceMacAddress;
        this.destMacAddress = packet.destMacAddress;
    }

    /**
     * This constructor creates a UDPPacket instance from its raw representation
     * @param packet a byte[] that stores the raw packet (already determined to be UDP)
     * @param timestamp the time the packet was captured
     */
    public UDPPacket(byte[] packet, long timestamp){
        super(packet,timestamp);

        int srcPortOffset = Utils.etherHeaderLength +
                Utils.getIPHeaderLength(packet) + inUDPHeaderSrcPortOffset;
        this.src_port = Utils.convertShort(packet, srcPortOffset);

        int dstPortOffset = Utils.etherHeaderLength +
                Utils.getIPHeaderLength(packet) + inUDPHeaderDstPortOffset;
        this.dst_port = Utils.convertShort(packet, dstPortOffset);

        int payloadDataStart =  Utils.etherHeaderLength +
                Utils.getIPHeaderLength(packet) + Utils.udpHeaderLength;
        byte[] data = new byte[0];
        if((packet.length - payloadDataStart) > 0){
            data = new byte[packet.length - payloadDataStart];
            System.arraycopy(packet, payloadDataStart, data, 0, data.length);
        }
        this.data = data;
    }

    /**
     * This constructor is only used by an external program using my library and can be safely removed.
     */
    public UDPPacket(long timestamp, String srcMAC, String destMAC, InetAddress srcIP, InetAddress dstIP, int srcPort,
                     int destPort, byte[] data){

        super(timestamp, srcMAC, destMAC, srcIP, dstIP);
        this.src_port = srcPort;
        this.dst_port = destPort;
        this.data = data;
    }

    @Override
    public String toString(){
        return String.format(
                /*"-----UDP PACKET-----%nTimeStamp: %d%nSRC MAC: %s%nDST MAC: %s%nSRC IP: %s%nDEST IP: %s%nSRC PORT: %d%n" +
                        "DEST PORT: %d%nPAYLOAD LEN: %d%n", */
                "-----UDP PACKET-----%nTimeStamp: %d%nSRC MAC: %s%nDST MAC: %s%nSRC IP: %s%nDEST IP: %s%nSRC PORT: %d%n" +
                        "DEST PORT: %d%n",
                this.timestamp/1000, this.sourceMacAddress, this.destMacAddress, this.src_ip.getHostAddress(),
                this.dst_ip.getHostAddress(), this.src_port, this.dst_port/*, this.data.length*/);
    }
}
