package uk.ac.gla.atanaspam.pcapj;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;

/**
 * This class implements the capability to introduce patterns into the already exported
 * data set. This is done by injecting a packet that has pre-defined values for fields
 * at a varying frequency, thus creating the pattern.
 * @author atanaspam
 * @created 15/11/2015
 * @version 0.6
 */

public class PacketGenerator {

    private static final Logger LOG = LoggerFactory.getLogger(PacketGenerator.class);
    long anomalousPacketsEmitted;
    int signature;
    int anomalousTrafficPercentage;
    ArrayList<TCPFlags> flags;
    ArrayList<InetAddress> srcAddresses;
    ArrayList<InetAddress> dstAddresses;
    ArrayList<Integer> srcPorts;
    ArrayList<Integer> dstPorts;
    ArrayList<BasicPacket> packets;
    ArrayList<PacketContents> packetContents;
    int packetsTillAnomaly;
    int nextFlag;
    int nextSrcAddress;
    int nextDstAddress;
    int nextSrcPort;
    int nextDstPort;
    int nextPacket;
    int nextPacketContents;
    TCPPacket p ;

    /**
     * A constructor that sets default values for all settings.
     */
    public PacketGenerator(String path, boolean vlanEnabled, boolean verbose){
        anomalousPacketsEmitted = 0;
        packets = new ArrayList<BasicPacket>();
        this.signature = 0;
        this.anomalousTrafficPercentage = 10;
        packetsTillAnomaly = 100 / anomalousTrafficPercentage;
        this.flags = new ArrayList<TCPFlags>();
        TCPFlags flag = new TCPFlags(false,false,false,true,false,false,true,false);
        flags.add(flag);
        this.srcAddresses = new ArrayList<InetAddress>();
        this.dstAddresses = new ArrayList<InetAddress>();
        this.packetContents = new ArrayList<PacketContents>();
        try {
            srcAddresses.add(InetAddress.getByName("192.168.1.1"));
            dstAddresses.add(InetAddress.getByName("192.168.0.1"));
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        this.srcPorts = new ArrayList<Integer>();
        this.dstPorts = new ArrayList<Integer>();
        srcPorts.add(80);
        dstPorts.add(80);
        try {
            packetContents.add(new PacketContents("1".getBytes("UTF-8")));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        nextDstAddress = 0;
        nextSrcAddress = 0;
        nextFlag = 0;
        nextDstPort = 0;
        nextSrcPort = 0;
        nextPacket = 0;
        nextPacketContents = 0;
        p =  new TCPPacket(1445457108, "FF:FF:FF:FF:FF", "FF:FF:FF:FF:FF", null, null,
                0, 0, null, new PacketContents(new byte[1]));
        PcapParser pcapParser = new PcapParser();
        pcapParser.setVlanEnabled(vlanEnabled);
        pcapParser.setVerbose(verbose);
        if(pcapParser.openFile(path) < 0) {
            LOG.error("Failed to open  file" + ", exiting.");
            System.exit(-1);
        }
        BasicPacket packet = pcapParser.getPacket();
        while(packet != BasicPacket.EOF){
            if(!(packet instanceof IPPacket)){
                //LOG.warn("Processed an unknown packet");
                packet = pcapParser.getPacket();
                continue;
            }
            packets.add(packet);
            packet = pcapParser.getPacket();

        }
        LOG.info("Added "+ packets.size() + " packets");

    }

    /**
     * This method customizes the PacketGenerator mode and settings.
     * @param srcIP an ArrayList of possible Source IP addresses
     * @param dstIP an ArrayList of possible Destination IP addresses
     * @param srcPort an ArrayList of possible Source ports
     * @param dstPort an ArrayList of possible Destination ports
     * @param flags an ArrayList of possible TCP flags
     * @param sig The integer representation of the current attack (pattern) simulated
     */
    public void configure(ArrayList<InetAddress> srcIP, ArrayList<InetAddress> dstIP, ArrayList<Integer> srcPort,
                          ArrayList<Integer> dstPort, ArrayList<boolean[]> flags, int sig, ArrayList<PacketContents> packetContents){
        for (boolean[] a : flags){ this.flags.add(new TCPFlags(a));}
        for (InetAddress a : srcIP){ srcAddresses.add(a);}
        for (InetAddress a : dstIP){ dstAddresses.add(a);}
        for(Integer n : srcPort){ srcPorts.add(n);}
        for(Integer n : dstPort){ dstPorts.add(n);}
        for(PacketContents p : packetContents){ this.packetContents.add(p);}
        switch (sig) {
            case 0: {
                // Disable
                anomalousTrafficPercentage = 1;
                return;
            }
            case 1: {
                // Simulate a DOS attack
                signature = 1;
                return;
            }
            case 2: {
                // Simulate a DDOS attack
                signature = 2;
                try {
                    for (byte i = 0; i < 127; i++) {
                        byte[] ipAddr = new byte[]{0, 0, 0, i};
                        InetAddress addr = InetAddress.getByAddress(ipAddr);
                        srcAddresses.add(addr);
                    }
                } catch (UnknownHostException e) {
                    e.printStackTrace();
                }
                return;
            }

            case 3: {
                // Simulate a SYN flood attack
                signature = 3;
                this.flags.clear();
                this.flags.add(new TCPFlags(new boolean[]{false,false,false,false,false,false,true,false}));
                return;
            }
            case 4: {
                // Simulate Invalid flags
                this.flags.clear();
                // Since no flag is set, this is an invalid combination.
                this.flags.add(new TCPFlags(new boolean[]{false,false,false,false,false,false,false,false}));
                return;
            }
            case 5: {
                // Simulate an Application layer attack ()
                signature = 5;
                try {
                    //this.packetContents.add(new PacketContents("".getBytes("UTF-8")));
                    this.packetContents.add(new PacketContents("aaa".getBytes("UTF-8")));
                } catch (UnsupportedEncodingException e) {
                }
                return;
            }
            default: {
                // Disable
                anomalousTrafficPercentage = 1;
                return;
            }
        }
    }

    /**
     * Resets the settings to the default state.
     */
    public void clear() {packetsTillAnomaly = 100 / anomalousTrafficPercentage;
        this.flags = new ArrayList<TCPFlags>();
        TCPFlags flag = new TCPFlags(false,false,false,true,false,false,true,false);
        flags.add(flag);
        this.srcAddresses = new ArrayList<InetAddress>();
        this.dstAddresses = new ArrayList<InetAddress>();
        this.packetContents = new ArrayList<PacketContents>();
        try {
            srcAddresses.add(InetAddress.getByName("192.168.1.1"));
            dstAddresses.add(InetAddress.getByName("192.168.0.1"));
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        this.srcPorts = new ArrayList<Integer>();
        this.dstPorts = new ArrayList<Integer>();
        srcPorts.add(80);
        dstPorts.add(80);
        nextDstAddress = 0;
        nextSrcAddress = 0;
        nextFlag = 0;
        nextDstPort = 0;
        nextSrcPort = 0;
        nextPacket = 0;
        nextPacketContents = 0;
    }

    /**
     * This method sets new values to the field choices
     * @param srcIP an ArrayList of possible Source IP addresses
     * @param dstIP an ArrayList of possible Destination IP addresses
     * @param srcPort an ArrayList of possible Source ports
     * @param dstPort an ArrayList of possible Destination ports
     * @param flags an ArrayList of possible TCP flags
     * @param sig The integer representation of the current attack (pattern) simulated
     * @param anomalyPercent the percentage of anomalous data in the data generated
     */
    public void set(ArrayList<InetAddress> srcIP, ArrayList<InetAddress> dstIP, ArrayList<Integer> srcPort,
                          ArrayList<Integer> dstPort, ArrayList<TCPFlags> flags, ArrayList<PacketContents> packetContents,
                            int sig, int anomalyPercent) {

        this.anomalousTrafficPercentage = anomalyPercent;
        packetsTillAnomaly = 100 / anomalousTrafficPercentage;
        this.srcAddresses = srcIP;
        this.dstAddresses = dstIP;
        this.srcPorts = srcPort;
        this.dstPorts = dstPort;
        this.flags = flags;
        this.signature = sig;
        this.packetContents = packetContents;
    }

    /**
     * This method returns a single packet that is part of a specific pattern
     * If anomalousTrafficPercentage is set to 1 this method iterates over the statically imported
     * data and does not introduce any patterns.
     * @return A packet object
     */
    public BasicPacket getPacket(){
        if (packetsTillAnomaly == 1 && anomalousTrafficPercentage != 1){
            return getAnomalousPacket();
        }
        else{
            return getOrdinaryPacket();
        }
    }

    /**
     * Get the number of anomalous packets emitted until now
     * @return the number of packets
     */
    public long getAnomalousPacketsEmitted() {
        return anomalousPacketsEmitted;
    }

    /**
     * Setter method that changes the anomalous traffic percentage and adjusts the
     * packetsTillAnomaly accordingly.
     * @param anomalousTrafficPercentage
     */
    public void setAnomalousTrafficPercentage(int anomalousTrafficPercentage) {
        this.anomalousTrafficPercentage = anomalousTrafficPercentage;
        if(anomalousTrafficPercentage != 1){
            packetsTillAnomaly = 100 / anomalousTrafficPercentage;
        }

    }

    /**
     * Obtain a packet with fields set to anomalous values (Anomalous packet)
     * @return the anomalous packet
     */
    private BasicPacket getAnomalousPacket(){
        //IPPacket sample = (IPPacket) packets.get(nextPacket);
        p.setSrc_ip(srcAddresses.get(nextSrcAddress));
        p.setDst_ip(dstAddresses.get(nextDstAddress));
        p.setSrc_port(srcPorts.get(nextSrcPort));
        p.setDst_port(dstPorts.get(nextDstPort));
        p.setFlags(flags.get(nextFlag));
        p.setData(packetContents.get(nextPacketContents));
        nextSrcAddress = ++nextSrcAddress % srcAddresses.size();
        nextDstAddress = ++nextDstAddress % dstAddresses.size();
        nextSrcPort = ++nextSrcPort % srcPorts.size();
        nextDstPort = ++nextDstPort % dstPorts.size();
        nextFlag = ++nextFlag % flags.size();
        nextPacketContents = ++nextPacketContents % packetContents.size();
        packetsTillAnomaly = 100 /anomalousTrafficPercentage;
        anomalousPacketsEmitted++;
        return p;
    }

    /**
     * Obtain a packet from the static export
     * @return the ordinary packet
     */
    private BasicPacket getOrdinaryPacket(){
        packetsTillAnomaly--;
        nextPacket = ++nextPacket % packets.size();
        return packets.get(nextPacket);
    }

    /**
     * An example to test the functionality
     * @param args
     */
    public static void main (String[] args){
//        PacketGenerator p = new PacketGenerator("test.pcap", true, false);
//        p.configure(new ArrayList<InetAddress>(), new ArrayList<InetAddress>(), new ArrayList<Integer>(), new ArrayList<Integer>(),
//                new ArrayList<boolean[]>(), 0);
//        for (int i=0; i<400; i++){
//            System.out.println(p.getPacket());
//        }
//        System.out.println("-----------------------------------------------------------------------------------");
//        p.configure(new ArrayList<InetAddress>(), new ArrayList<InetAddress>(), new ArrayList<Integer>(), new ArrayList<Integer>(),
//                new ArrayList<boolean[]>(), 1);
//        p.setAnomalousTrafficPercentage(10);
//        for (int i=0; i<400; i++){
//            System.out.println(p.getPacket());
//        }
        PacketGenerator p;
        p = new PacketGenerator("/Users/atanaspam/Documents/Versoned_Projects/RTDCONN/univ1_pt1.pcap", true, false);
        ArrayList<InetAddress> a = new ArrayList<InetAddress>();
        try {
            a.add(InetAddress.getByName("10.10.1.1"));
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        p.configure(a, new ArrayList<InetAddress>(), new ArrayList<Integer>(),
                new ArrayList<Integer>(), new ArrayList<boolean[]>(),5, new ArrayList<PacketContents>());
        p.setAnomalousTrafficPercentage(20);
        for (int i=0; i<400; i++){
            System.out.println(p.getPacket());
        }
    }


}

