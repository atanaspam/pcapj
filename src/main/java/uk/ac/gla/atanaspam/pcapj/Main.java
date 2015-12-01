package uk.ac.gla.atanaspam.pcapj;

/**
 * @author atanaspam
 * @version 0.1
 * @created 01/12/2015
 */
public class Main {
    public static void main(String[] args) {
        PcapParser pcapParser = new PcapParser();
        String path = "YOUR PATH HERE";             //CHANGEME
        if (pcapParser.openFile(path) < 0) {
            System.err.println("Failed to open " + path + ", exiting.");
            return;
        }
        BasicPacket packet = pcapParser.getPacket();
        while (packet != BasicPacket.EOF) {
            if (!(packet instanceof IPPacket)) {
                packet = pcapParser.getPacket();
                continue;
            }
            System.out.println(packet);
            packet = pcapParser.getPacket();
        }
        pcapParser.closeFile();
    }
}
