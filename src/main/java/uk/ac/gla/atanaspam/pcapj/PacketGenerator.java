package uk.ac.gla.atanaspam.pcapj;


import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;

/**
 * This class implements the capability to introduce patterns into the already exported
 * data set. This is done by injecting a packet that has pre-define values for fields
 * at a varying frequency, thus creating the pattern.
 * @author atanaspam
 * @created 15/11/2015
 * @version 0.6
 */

public class PacketGenerator {

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
    public PacketGenerator(){
        packets = new ArrayList<BasicPacket>();
        this.signature = 0;
        this.anomalousTrafficPercentage = 10;
        packetsTillAnomaly = 100 / anomalousTrafficPercentage;
        this.flags = new ArrayList<boolean[]>();
        boolean[] flag ={false,false,false,false,false,false};
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
        if(pcapParser.openFile("/Users/atanaspam/Desktop/DumpFile03.pcap") < 0){
            System.err.println("Failed to open  file" + ", exiting.");
            return;
        }
        BasicPacket packet = pcapParser.getPacket();
        while(packet != BasicPacket.EOF){
            if(!(packet instanceof IPPacket)){
                packet = pcapParser.getPacket();
                //packets.add(packet);
                continue;
            }
            packet = pcapParser.getPacket();
            packets.add(packet);
        }
        System.out.println("Added "+ packets.size() + " packets");

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
        switch (sig){
            case 0: {
                // Custom, only import contents from settngs.
                break;
            }
            case 1:{
                // Simulate a DOS attack
                signature = 1;
                anomalousTrafficPercentage = 20;
                packetsTillAnomaly = 100 / anomalousTrafficPercentage;
                for (boolean[] a : flags){ flags.add(a);}
                for (InetAddress a : srcIP){ srcAddresses.add(a);}
                for (InetAddress a : dstIP){ dstAddresses.add(a);}
                for(Integer n : srcPort){ srcPorts.add(n);}
                for(Integer n : dstPort){ dstPorts.add(n);}
                return;
            }
            case 2: {
                // Simulate a DDOS attack
            }

            case 3: {
                //Simulate a SYN flood
            }
        }

    }

    /**
     * This method returns a single packet that is part of a specific pattern
     * If anomalousTrafficPercentage is set to 1 this method iterates over the statically imported
     * data and does not introduce any patterns.
     * @return A packet object
     */
    public BasicPacket getPacket(){
        if (packetsTillAnomaly == 1 && anomalousTrafficPercentage != 1){
            TCPPacket p =  new TCPPacket(1445457108, "FF:FF:FF:FF:FF", "FF:FF:FF:FF:FF",
                    srcAddresses.get(nextSrcAddress), dstAddresses.get(nextDstAddress), srcPorts.get(nextSrcPort),
                    dstPorts.get(nextDstPort), flags.get(nextFlag));
            nextSrcAddress = nextSrcAddress++ % srcAddresses.size();
            nextDstAddress = nextDstAddress++ % dstAddresses.size();
            nextSrcPort = nextSrcPort++ % srcPorts.size();
            nextDstPort = nextDstPort++ % dstPorts.size();
            nextFlag = nextFlag++ % flags.size();
            packetsTillAnomaly = 100 /anomalousTrafficPercentage;
            return p;
        }
        else{
            packetsTillAnomaly--;
            nextPacket = nextPacket++ % packets.size();
            System.out.println(nextPacket);
            return packets.get(nextPacket);
        }
    }

    /**
     * An example to test the functionality
     * @param args
     */
    public static void main (String[] args){
        PacketGenerator p = new PacketGenerator();
        p.configure(new ArrayList<InetAddress>(), new ArrayList<InetAddress>(), new ArrayList<Integer>(), new ArrayList<Integer>(),
                new ArrayList<boolean[]>(), 1);
        for (int i=0; i<100; i++){
            System.out.println(p.getPacket());
        }
    }


}
