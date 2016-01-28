package uk.ac.gla.atanaspam.pcapj;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.*;

/**
 * This class stores data extracted from an Ethernet frame.
 * @author atanaspam
 * @version 0.4
 */
public class IPPacket extends BasicPacket{

    private static final Logger LOG = LoggerFactory.getLogger(IPPacket.class);

    final int ipSrcOffset = 12; //Offset from etherHeader end
    final int ipDstOffset = 16; //Offset from etherHeader end

    protected long timestamp;
    protected InetAddress src_ip;
    protected InetAddress dst_ip;
    protected String sourceMacAddress;
    protected String destMacAddress;

    public long getTimestamp() {
        return timestamp;
    }

    public InetAddress getSrc_ip() {
        return src_ip;
    }

    public String getSourceMacAddress() {
        return sourceMacAddress;
    }

    public InetAddress getDst_ip() {
        return dst_ip;
    }

    public String getDestMacAddress() {
        return destMacAddress;
    }

    public void setSrc_ip(InetAddress src_ip) {
        this.src_ip = src_ip;
    }

    public void setDst_ip(InetAddress dst_ip) {
        this.dst_ip = dst_ip;
    }

    public void setSourceMacAddress(String sourceMacAddress) {
        this.sourceMacAddress = sourceMacAddress;
    }

    public void setDestMacAddress(String destMacAddress) {
        this.destMacAddress = destMacAddress;
    }

    /**
     * Basic constructor used to create initial object.
     * Used when nothing else is known for that packet.
     * @param timestamp The time when the packet was captured
     */
    public IPPacket(long timestamp){
        this.timestamp = timestamp;
    }

    /**
     * A more-advanced constructor that sets all the Eth frame data that is captured.
     *
     * @param packet A byte[] that stores the raw frame
     * @param timestamp The time when the packet was captured
     */
    public IPPacket(byte[] packet, long timestamp){

        this.timestamp = timestamp;

        byte[] macAddress = new byte[6];
        /**
         * First copy the destination MAC address from the raw data and parse it to a string.
         */
        System.arraycopy(packet, 0, macAddress, 0, macAddress.length);
        this.destMacAddress = Utils.getMacAddress(macAddress);

        /**
         * Copy the source MAC address from the raw data and parse it to a string.
         */
        System.arraycopy(packet, 6, macAddress, 0, macAddress.length);
        this.sourceMacAddress = Utils.getMacAddress(macAddress);

        /**
         * Copy the source IP address from the raw data and parse it.
         */
        byte[] srcIP = new byte[4];
        System.arraycopy(packet, ipSrcOffset + Utils.etherHeaderLength,
                srcIP, 0, srcIP.length);
        try{
            this.src_ip = InetAddress.getByAddress(srcIP);
        }catch(Exception e) {
            LOG.error("An error occured while parsing the src_ip address.");
        }

        /**
         * Copy the dest IP address from the raw data and parse it.
         */
        byte[] dstIP = new byte[4];
        System.arraycopy(packet, ipDstOffset + Utils.etherHeaderLength,
                dstIP, 0, dstIP.length);
        try{
            this.dst_ip = InetAddress.getByAddress(dstIP);
        }catch(Exception e){
            LOG.error("An error occurred while parsing the src_ip address.");
        }
    }

    /**
     * This constructor is only used by an external program using my library and can be safely removed.
     */
    public IPPacket(long timestamp, String srcMAC, String destMAC, InetAddress srcIP, InetAddress dstIP){
        super();
        this.timestamp = timestamp;
        this.sourceMacAddress = srcMAC;
        this.destMacAddress = destMAC;
        this.src_ip = srcIP;
        this.dst_ip = dstIP;

    }

    @Override
    public String toString(){
        return String.format(
                "-----PACKET-----%nTimeStamp: %d%nSRC MAC: %s%nDST MAC: %s%nSRC IP: %s%nDEST IP: %s%n",
                this.timestamp/1000, this.sourceMacAddress, this.destMacAddress, this.src_ip.getHostAddress(),
                this.dst_ip.getHostAddress());
    }
}
