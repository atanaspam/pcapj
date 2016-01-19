package uk.ac.gla.atanaspam.pcapj;

import java.io.File;

/**
 * @author atanaspam
 * @version 0.1
 * @created 01/12/2015
 */
public class Main {
    public static void main(String[] args) {
        PcapParser pcapParser = new PcapParser();
        String path = args[0];             //Your path can go here
        File f = new File(path);
        System.out.println(f.getAbsoluteFile());
        pcapParser.setVlanEnabled(true);
        pcapParser.setVerbose(false);
        if(pcapParser.openFile(path) < 0) {
            System.out.println("Failed to open  file" + ", exiting.");
            System.exit(-1);
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
