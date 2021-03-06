package uk.ac.gla.atanaspam.pcapj;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class stores various constants and auxiliary methods used to parse packets
 * @author atanaspam
 * @version 0.4
 */
public class Utils {

    private static final Logger LOG = LoggerFactory.getLogger(Utils.class);

    public static final int globalHeaderLength = 24;
    public static int vlanHeaderLength = 4;
    public static int etherHeaderLength = 14;
    public static final int udpHeaderLength = 8;

    public static int verIHLOffset = etherHeaderLength; // the offset is the same as the ether header end
    public static int etherTypeOffset = 12;
    public static final int ipProtoOffset = 9; //Offset from etherHeader end

    public static boolean vlanEnabled = false;
    public static final int ipProtoTCP = 6;
    public static final int ipProtoUDP = 17;
    public static final int etherTypeIPv4 = 0x800;
    public static final int etherTypeIPv6 = 0x86DD;
    public static final long pcapMagicNumber = 0xA1B2C3D4;



    /**
     * Retrieves the EtherType of a packet that is not supported.
     * @param packet a byte[] storing raw packet information.
     * @return a String representing the hex Ethertype code.
     */
    public static String getProtocolType(byte[] packet){
        return Integer.toHexString(packet[ipProtoOffset + etherHeaderLength]);
    }


    /**
     * Obtains the length of the IP header.
     * @param packet a byte[] storing raw packet information.
     * @return the length.
     */
    public static int getIPHeaderLength(byte[] packet){
        return (packet[verIHLOffset] & 0xF) * 4;
    }

    /**
     * Obtains the end of the TCP header index in the packet param
     * @param packet a byte[] storing raw packet information.
     * @return the index where the header ends and the payload starts
     */
    public static int getTCPHeaderLength(byte[] packet){
        final int inTCPHeaderDataOffset = 12;

        int dataOffset = etherHeaderLength +
                getIPHeaderLength(packet) + inTCPHeaderDataOffset;
        return ((packet[dataOffset] >> 4) & 0xF) * 4;
    }

    /**
     * Converts a 4 byte int to a decimal int.
     * @param data a byte[] storing a 4 byte int.
     * @return a decimal Integer that is equal to the byte[] integer.
     */
    public static long convertInt(byte[] data){

        return ((data[3] & 0xFF) << 24) | ((data[2] & 0xFF) << 16) |
                ((data[1] & 0xFF) << 8) | (data[0] & 0xFF);
    }

    /**
     * Converts a 4 byte integer that is stored in a byte[] and converts it to a decimal int
     * @param data the byte[] that stores the Integer of interest
     * @param offset the offset into the data[]
     * @return a decimal Integer that is equal to the byte[] integer
     */
    public static long convertInt(byte[] data, int offset){
        byte[] target = new byte[4];
        System.arraycopy(data, offset, target, 0, target.length);
        return convertInt(target);
    }

    /**
     * This method converts a 2 byte int to a decimal int
     * @param data a byte[] storing a 2 byte int
     * @return a decimal Integer that is equal to the byte[] integer
     */
    public static int convertShort(byte[] data){
        return ((data[1] & 0xFF) | (data[0] & 0xFF) << 8) ;
    }

    /**
     * Converts a 2 byte integer that is stored in a byte[] to a decimal int.
     * @param data the byte[] that stores the Integer that needs to be extracted.
     * @param offset the offset into the data[].
     * @return a decimal Integer that is equal to the byte[] integer.
     */
    public static int convertShort(byte[] data, int offset){
        byte[] target = new byte[2];
        System.arraycopy(data, offset, target, 0, target.length);
        return convertShort(target);
    }

    /**
     * Converts a byte[6] that stores a mac address to an easily readable ':' separated mac address String.
     * @param source a byte[] that stores a hexadecimal mac address.
     * @return a String representation of the Hex MAC address.
     */
    public static String getMacAddress(byte[] source){
        StringBuilder str = null;
        try {
            String rawString = javax.xml.bind.DatatypeConverter.printHexBinary(source);
            str = new StringBuilder(rawString);
            int n = 0;
            for (int i=0; i<str.length(); i++){
                if (n==2){
                    str.insert(i, ':');
                    n=0;
                }
                else {
                    n++;
                }
            }
            return str.toString();
        }catch (Exception e){
            LOG.error("An error has occurred while parsing a MAC address");
        }
        return null;
    }

    /**
     * Checks if the packet supplied is a known IP packet (IPv4).
     * @param packet a byte[] storing a raw packet.
     * @return true if the packet is IPv4, false otherwise.
     */
    public static boolean isIPPacket(byte[] packet){
        int etherType = convertShort(packet, etherTypeOffset);
        //LOG.error(etherType+" offset: "+etherTypeOffset);
        return etherType == etherTypeIPv4;
    }

    /**
     * Checks if the packet supplied is a UDP packet.
     * @param packet a byte[] storing a raw packet.
     * @return true if the packet is UDP, false otherwise.
     */
    public static boolean isUDPPacket(byte[] packet){
        if(!isIPPacket(packet))
            return false;
        return packet[ipProtoOffset + etherHeaderLength] == ipProtoUDP;
    }

    /**
     * Checks if the packet supplied is a TCP packet.
     * @param packet a byte[] storing a raw packet.
     * @return true if the packet is TCP, false otherwise.
     */
    public static boolean isTCPPacket(byte[] packet){
        if(!isIPPacket(packet))
            return false;
        return packet[ipProtoOffset + etherHeaderLength] == ipProtoTCP;
    }

    /**
     * Calculates a custom offset within the TCP segment of a packet.
     * Used with byte[] raw packet representation
     * @param IPHeaderLength the Length of the IP part of the header.
     * @param customOffset the custom offset that needs to be added.
     * @return the custom offset.
     */
    public static int calculateTCPoffset(int IPHeaderLength, int customOffset){
        return etherHeaderLength +
                IPHeaderLength + customOffset;
    }

    /**
     * This method uses a leading 1 byte[]
     * This method converts a 4 byte int to a decimal int
     * @param data a byte[] storing a 4 byte int
     * @return a decimal Integer that is equal to the byte[] integer
     */
    public static long convertLong(byte[] data){
        long value = 0;
        for (int i = 0; i < data.length; i++)
        {
            value = (value << 8) + (data[i] & 0xff);
        }
        return value;
    }

    /**
     * This method uses a leading 1 byte[]
     * This method converts a 4 byte integer that is stored in a byte[] and converts it to a decimal int
     * @param data the byte[] that stores the Integer of interest
     * @param offset the offset into the data[]
     * @return a decimal Integer that is equal to the byte[] integer
     */
    public static long convertLong(byte[] data, int offset){
        byte[] target = new byte[4];
        System.arraycopy(data, offset, target, 0, target.length);
        return convertLong(target);
    }

    /**
     * AN Aux function to obtain the value of a flag.
     * Used when getting the TCP flag values in TCPPacket.
     * @param value a byte containing the required bits.
     * @param bit the index of the bit of interest.
     * @return true if bit is 1 false if not.
     */
    public static boolean isSet(byte value, int bit){
        return (value&(1<<bit))!=0;
    }


}
