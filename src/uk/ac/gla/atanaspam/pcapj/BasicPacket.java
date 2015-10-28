package uk.ac.gla.atanaspam;

/**
 * This class represents the most generic packet.
 * A packet is a BasicPacket only if it is unknown to the underlying logic.
 * @author atanaspam
 * @version 0.3
 */
public class BasicPacket{

    private String type;

    /**
     * Default constructor
     */
    BasicPacket(){}

    /**
     * Constructor that specifies the packet type according to the Ethertype detected.
     * @param s A hex string that caries the Ethertype detected.
     */
    BasicPacket(String s){
        this.type = s;
    }
    public static final BasicPacket EOF = new BasicPacket();

    public String toString(){
        return "No Info";
    }

}
