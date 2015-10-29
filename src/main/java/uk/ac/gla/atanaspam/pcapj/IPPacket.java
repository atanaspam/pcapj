package uk.ac.gla.atanaspam.pcapj;

import java.net.*;
import java.util.Arrays;

/**
 * This class stores data extracted from an Ethernet frame.
 * @author atanaspam
 * @version 0.4
 */
public class IPPacket extends BasicPacket{

    public long timestamp;
    
    public InetAddress src_ip;
    public InetAddress dst_ip;
    public String sourceMacAddress;
    public String destMacAddress;

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
        System.arraycopy(packet, Utils.ipSrcOffset,
                srcIP, 0, srcIP.length);
        try{
            this.src_ip = InetAddress.getByAddress(srcIP);
        }catch(Exception e){
            System.out.println("An error occured while parsing the src_ip address.");
            //return null;
        }

        /**
         * Copy the dest IP address from the raw data and parse it.
         */
        byte[] dstIP = new byte[4];
        System.arraycopy(packet, Utils.ipDstOffset,
                dstIP, 0, dstIP.length);
        try{
            this.dst_ip = InetAddress.getByAddress(dstIP);
        }catch(Exception e){
            System.out.println("An error occured while parsing the src_ip address.");
            //return null;
        }
    }

    /**
     * This constructor is only used by an external program using my library and can be safely removed.
     */
    public IPPacket(long timestamp, String srcMAC, String destMAC, InetAddress srcIP, InetAddress dstIP){
        this.timestamp = timestamp;
        this.sourceMacAddress = srcMAC;
        this.destMacAddress = destMAC;
        this.src_ip = srcIP;
        this.dst_ip = dstIP;

    }

    /**
     * A simple toString method.
     * @return A String representing everything we know about this packet.
     */
    public String toString(){
        return String.format(
                "-----PACKET-----%nTimeStamp: %d%nSRC MAC: %s%nDST MAC: %s%nSRC IP: %s%nDEST IP: %s%n",
                this.timestamp/1000, this.sourceMacAddress, this.destMacAddress, this.src_ip.getHostAddress(),
                this.dst_ip.getHostAddress());
    }
}
