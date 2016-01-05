package uk.ac.gla.atanaspam.pcapj;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    int signature;
    int anomalousTrafficPercentage;
    ArrayList<boolean[]> flags;
    ArrayList<InetAddress> srcAddresses;
    ArrayList<InetAddress> dstAddresses;
    ArrayList<Integer> srcPorts;
    ArrayList<Integer> dstPorts;
    ArrayList<BasicPacket> packets;
    int packetsTillAnomaly;
    int nextFlag;
    int nextSrcAddress;
    int nextDstAddress;
    int nextSrcPort;
    int nextDstPort;
    int nextPacket;

    /**
     * A constructor that sets default values for all settings.
     */
    public PacketGenerator(String path, boolean vlanEnabled, boolean verbose){
        packets = new ArrayList<BasicPacket>();
        this.signature = 0;
        this.anomalousTrafficPercentage = 10;
        packetsTillAnomaly = 100 / anomalousTrafficPercentage;
        this.flags = new ArrayList<boolean[]>();
        boolean[] flag ={false,false,false,true,false,false,true,false};
        flags.add(flag);
        this.srcAddresses = new ArrayList<InetAddress>();
        this.dstAddresses = new ArrayList<InetAddress>();
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
                          ArrayList<Integer> dstPort, ArrayList<boolean[]> flags, int sig){
        for (boolean[] a : flags){ flags.add(a);}
        for (InetAddress a : srcIP){ srcAddresses.add(a);}
        for (InetAddress a : dstIP){ dstAddresses.add(a);}
        for(Integer n : srcPort){ srcPorts.add(n);}
        for(Integer n : dstPort){ dstPorts.add(n);}

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
                flags.clear();
                flags.add(new boolean[]{false,false,false,false,false,false,true,false});
                return;
            }
            case 4: {
                // Simulate Invalid flags
                flags.clear();
                // Since no flag is set, this is an invalid combination.
                flags.add(new boolean[]{false,false,false,false,false,false,false,false});
            }
            case 5: {
                // Simulate an Application layer attack ()
            }
            default: {
                // Disable
                anomalousTrafficPercentage = 1;
                return;
            }
        }

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
                          ArrayList<Integer> dstPort, ArrayList<boolean[]> flags, int sig, int anomalyPercent) {

        this.anomalousTrafficPercentage = anomalyPercent;
        packetsTillAnomaly = 100 / anomalousTrafficPercentage;
        this.srcAddresses = srcIP;
        this.dstAddresses = dstIP;
        this.srcPorts = srcPort;
        this.dstPorts = dstPort;
        this.flags = flags;
        this.signature = sig;
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

    public void setAnomalousTrafficPercentage(int anomalousTrafficPercentage) {
        this.anomalousTrafficPercentage = anomalousTrafficPercentage;
    }

    private BasicPacket getAnomalousPacket(){
        //IPPacket sample = (IPPacket) packets.get(nextPacket);
        TCPPacket p =  new TCPPacket(1445457108, "FF:FF:FF:FF:FF", "FF:FF:FF:FF:FF",
                srcAddresses.get(nextSrcAddress), dstAddresses.get(nextDstAddress), srcPorts.get(nextSrcPort),
                dstPorts.get(nextDstPort), flags.get(nextFlag), null);
        nextSrcAddress = ++nextSrcAddress % srcAddresses.size();
        nextDstAddress = ++nextDstAddress % dstAddresses.size();
        nextSrcPort = ++nextSrcPort % srcPorts.size();
        nextDstPort = ++nextDstPort % dstPorts.size();
        nextFlag = ++nextFlag % flags.size();
        packetsTillAnomaly = 100 /anomalousTrafficPercentage;
        return p;
    }

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
        PacketGenerator p = new PacketGenerator("/Users/atanaspam/Documents/Versoned Projects/RTDCONN/partial.pcap", true, true);
        p.configure(new ArrayList<InetAddress>(), new ArrayList<InetAddress>(), new ArrayList<Integer>(), new ArrayList<Integer>(),
                new ArrayList<boolean[]>(), 2);
        for (int i=0; i<400; i++){
            System.out.println(p.getPacket());
        }
    }


}

