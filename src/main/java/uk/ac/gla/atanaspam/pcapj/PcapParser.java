package uk.ac.gla.atanaspam.pcapj;

import java.io.*;
import java.lang.Exception;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is the entry point for that module.
 * A client will typically invoke OpenFile() and then GetPacket()
 * @author atanaspam
 * @version 0.5
 */
public class PcapParser{

	private static final Logger LOG = LoggerFactory.getLogger(PcapParser.class);

    private RandomAccessFile raf;
    private boolean verbose = false;
	private boolean vlanEnabled = false;
    private long fileOffset;

    public PcapParser(){
        fileOffset = 0;
    }

    /**
     * Specify if the packets processed contain a 802.1Q Header
     * This reflects on the constants specified in the Utils class
     * @param value the new setting
     */
	public void setVlanEnabled(boolean value) {
		if (value){
            Utils.etherHeaderLength = Utils.etherHeaderLength + Utils.vlanHeaderLength;
            Utils.etherTypeOffset = Utils.etherTypeOffset + Utils.vlanHeaderLength;
            Utils.verIHLOffset = Utils.verIHLOffset + Utils.vlanHeaderLength;
		} else if (this.vlanEnabled && !value){
            Utils.etherHeaderLength = Utils.etherHeaderLength - Utils.vlanHeaderLength;
            Utils.etherTypeOffset = Utils.etherTypeOffset - Utils.vlanHeaderLength;
            Utils.verIHLOffset = Utils.verIHLOffset - Utils.vlanHeaderLength;
		}
		this.vlanEnabled = value;
	}

	/**
     * Set the verbosity level.
     * @param newVerbose the new setting.
     */
    public void setVerbose(boolean newVerbose){
        this.verbose = newVerbose;
        if(newVerbose)
		    LOG.debug("Verbose Mode enabled");
        else
            LOG.debug("Verbose Mode disabled");
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
                raf.seek(fileOffset);
				read = this.raf.read(data, offset, data.length - offset);
			}catch(Exception e){
                LOG.error("An error occurred while reading from the file : " + e.getMessage());
				break;
			}
			if(read == -1)
				break;

			offset = offset + read;
            fileOffset = fileOffset + read;
        }
        //LOG.info(fileOffset+"");
		if(read != data.length) {
            LOG.error("Could not read from file. File may be corrupted.");
            return -1;
        }
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
		byte[] globalHeader = new byte[Utils.globalHeaderLength];

		if(this.readBytes(globalHeader) == -1) {
            return -1;
        }
        if (verbose) {
            //LOG.info("Trafic type: " + Utils.convertInt(globalHeader, UtglobalHeaderSize-4));
            String header = String.format("Global Header : %s",
                    javax.xml.bind.DatatypeConverter.printHexBinary(globalHeader));
           LOG.info(header);
        }
		if(Utils.convertInt(globalHeader) != Utils.pcapMagicNumber) {
            LOG.error("PCAP file has wrong endianness");
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
            this.raf = new RandomAccessFile(new File(path), "r");
		}catch(FileNotFoundException e){
			LOG.error("Could not read from file, please check the path.");
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

		PcapPacketHeader pcapPacketHeader = new PcapPacketHeader();
		pcapPacketHeader.timestamp =
				(Utils.convertInt(header, inPcapPacketHeaderSecOffset) * 1000) +
						(Utils.convertInt(header, inPcapPacketHeaderUSecOffset) / 1000);

		pcapPacketHeader.packetSize =
				Utils.convertInt(header, PcapPacketHeader.capLenOffset);
        if (verbose) {
            String packetHeader = String.format("PCAP Packet Header : %s",
                    javax.xml.bind.DatatypeConverter.printHexBinary(header));
            LOG.info(packetHeader);
        }

		return pcapPacketHeader;
	}



    /**
     * This is a dispatcher method that calls the appropriate constructor according to the packet type.
     * @param packet a byte[] that contains the raw packet contents
     * @param timestamp the timestamp of the packet
     * @return the packet generated which can be UDPPacket, TCPPacket or BasicPacket
     */
	private BasicPacket buildPacket(byte[] packet, long timestamp){
		if(Utils.isUDPPacket(packet)){
            UDPPacket p = new UDPPacket(packet, timestamp);
            if (verbose)
                LOG.info(p.toString());
            return p;
        }
		else if(Utils.isTCPPacket(packet)) {
			TCPPacket p = new TCPPacket(packet, timestamp);
            if (verbose)
                LOG.info(p.toString());
            return p;
		}
		else if(Utils.isIPPacket(packet)) {
            IPPacket p =  new IPPacket(packet, timestamp);
            if (verbose)
                LOG.info(p.toString());
            return p;
        }
		else {
            BasicPacket p = new BasicPacket(Utils.getProtocolType(packet));
            if (verbose)
                LOG.info(p.toString());
            return p;
        }
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
            String packetStr = String.format("Packet : %s",
                    javax.xml.bind.DatatypeConverter.printHexBinary(packet));
            LOG.info(packetStr);
        }

        return new RawPacket(packet, pcapPacketHeader);
    }

    /**
     * Closes the File Handle.
     */
	public void closeFile(){
		try{
			raf.close();
		}catch(Exception e){
			LOG.warn("Unable to close file.");
		}
	}
}
