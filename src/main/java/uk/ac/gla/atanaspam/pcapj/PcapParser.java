package main.java.uk.ac.gla.atanaspam.pcapj;
import java.io.*;
import java.lang.Exception;
import java.util.Arrays;

/**
 * This class is the entry point for that module.
 * A client will typically invoke OpenFile() and then GetPacket()
 * @author atanaspam
 * @version 0.5
 */
public class PcapParser{

	public static final long pcapMagicNumber = 0xA1B2C3D4;
	public static final int globalHeaderSize = 24;

	private FileInputStream fis;
    private boolean verbose = false;

    /**
     * Set the verbosity level.
     * @param newVerbose the new setting.
     */
    public void setVerbose(boolean newVerbose){
        this.verbose = newVerbose;
    }

    /**
     * Check the current verbosity level.
     * @return the current setting.
     */
    public boolean getVerbose(){
        return this.verbose;
    }

    /**
     * This method reads as much data as it can fit into the provided byte[].
     * @param data a byte[] as a destination
     * @return 0 if successful, -1 if not
     */
	private synchronized int readBytes(byte[] data){
		int offset = 0;
		int read = -1;
		while(offset != data.length){
			try{
				read = this.fis.read(data, offset, data.length - offset);
			}catch(Exception e){
                System.out.println("An error occurred while reading from the file : " + e.getMessage());
				break;
			}
			if(read == -1)
				break;

			offset = offset + read;
		}
		if(read != data.length)
			return -1;
		else
			return 0;
	}

    /**
     * This method reads the PCAP file header and checks if it conforms to the required format.
     * If verbose is true the raw header will be printed to stdout.
     * @return 0 if everything is ok, -1 if an error occurs while reading and -2 if the format
     * is not recognised.
     */
	private int readGlobalHeader(){
		byte[] globalHeader = new byte[globalHeaderSize];

		if(this.readBytes(globalHeader) == -1) {
            return -1;
        }
        if (verbose) {
            //System.out.println("Trafic type: " + Utils.convertInt(globalHeader, globalHeaderSize-4));
            System.out.println("------------------------  Global Header ------------------------");
            System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(globalHeader));
        }
		if(Utils.convertInt(globalHeader) != pcapMagicNumber) {
            return -2;
        }
		return 0;
	}

    /**
     * This method opens a PCAP file and invokes readGlobalHeader to check if the file is recognised.
     * @param path The path to the file
     * @return 0 if everything is ok, -1 if an error has occurred.
     */
	public int openFile(String path){
		try{
			this.fis = new FileInputStream(new File(path));
		}catch(Exception e){
			e.printStackTrace();
			return -1;
		}

		if(this.readGlobalHeader() < 0)
			return -1;
		else
			return 0;
	}

    /**
     * This method reads a PCAP packet header and extracts the relevant data from it.
     * If verbose is true it also prints the raw header to stdout.
     * @return A packetHeader object with the timestamp and packetsize parameters extracted.
     */
	private synchronized PcapPacketHeader buildPcapPacketHeader(){
		final int inPcapPacketHeaderSecOffset = 0;
		final int inPcapPacketHeaderUSecOffset = 4;

		byte[] header = new byte[PcapPacketHeader.pcapPacketHeaderSize];
		if(this.readBytes(header) < 0)
			return null;
        if (verbose) {
            System.out.println("---------------------- PCAP Packet Header ----------------------");
            System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(header));
        }
		PcapPacketHeader pcapPacketHeader = new PcapPacketHeader();
		pcapPacketHeader.timestamp =
				(Utils.convertInt(header, inPcapPacketHeaderSecOffset) * 1000) +
						(Utils.convertInt(header, inPcapPacketHeaderUSecOffset) / 1000);

		pcapPacketHeader.packetSize =
				Utils.convertInt(header, PcapPacketHeader.capLenOffset);

		return pcapPacketHeader;
	}



    /**
     * This is a dispatcher method that calls the appropriate constructor according to the packet type.
     * @param packet a byte[] that contains the raw packet contents
     * @param timestamp the timestamp of the packet
     * @return the packet generated which can be UDPPacket, TCPPacket or BasicPacket
     */
	private BasicPacket buildPacket(byte[] packet, long timestamp){
		if(Utils.isUDPPacket(packet))
			return new UDPPacket(packet, timestamp);
		else if(Utils.isTCPPacket(packet))
			return new TCPPacket(packet, timestamp);
		else if(Utils.isIPPacket(packet))
			return new IPPacket(packet, timestamp);
		else
			return new BasicPacket(Utils.getProtocolType(packet));
	}

    /**
     * This method is called to retrieve a packet form a PCAP file
     * It first reads the packet header and checks if it is properly formatted.
     * This is also required in order to obtain the total size of the packet so that it can be allocated
     * if verbose is true the raw contents of the packet is printed to stdout.
     * @return a packet Object according to the raw packet's properties
     */
	public BasicPacket getPacket(){
		final int udpMinPacketSize = 42;
		final int tcpMinPacketSize = 54;

        /*
		PcapPacketHeader pcapPacketHeader = buildPcapPacketHeader();
		if(pcapPacketHeader == null)
			return BasicPacket.EOF;

		byte[] packet = new byte[(int)pcapPacketHeader.packetSize];
		if(this.readBytes(packet) < 0)
			return BasicPacket.EOF;
        if (verbose) {
            System.out.println("----------------------  Packet ----------------------");
            System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(packet));
        }
        */
        RawPacket raw = readPacket();
        if (raw == null){
            return BasicPacket.EOF;
        }
        else {

            if ((Utils.isUDPPacket(raw.getPacket()) && (raw.getPacket().length < udpMinPacketSize)) ||
                    (Utils.isTCPPacket(raw.getPacket()) && (raw.getPacket().length < tcpMinPacketSize)))
                return new BasicPacket(Utils.getProtocolType(raw.getPacket()));

            return buildPacket(raw.getPacket(), raw.getHeader().timestamp);
        }
	}

    private synchronized RawPacket readPacket(){

        PcapPacketHeader pcapPacketHeader = buildPcapPacketHeader();
        if(pcapPacketHeader == null)
            return null;

        byte[] packet = new byte[(int)pcapPacketHeader.packetSize];
        if(this.readBytes(packet) < 0)
            return null;
        if (verbose) {
            System.out.println("----------------------  Packet ----------------------");
            System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(packet));
        }

        return new RawPacket(packet, pcapPacketHeader);
    }

    /**
     * Closes the File Handle.
     */
	public void closeFile(){
		try{
			fis.close();
		}catch(Exception e){
			System.out.println("Unable to close file.");
		}
	}
}
