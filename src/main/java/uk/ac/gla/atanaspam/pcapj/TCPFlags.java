package uk.ac.gla.atanaspam.pcapj;

import java.io.Serializable;

/**
 * Represents the TCP flags in a packet and replaces the previous array representation.
 * @author atanaspam
 * @version 0.1
 * @created 19/01/2016
 */
public class TCPFlags implements Serializable{

    private static final long serialVersionUID = 0;

    boolean cwr;
    boolean ece;
    boolean urg;
    boolean ack;
    boolean psh;
    boolean rst;
    boolean syn;
    boolean fyn;

    public TCPFlags(boolean cwr, boolean ece, boolean urg, boolean ack, boolean psh, boolean rst, boolean syn, boolean fyn) {
        this.cwr = cwr;
        this.ece = ece;
        this.urg = urg;
        this.ack = ack;
        this.psh = psh;
        this.rst = rst;
        this.syn = syn;
        this.fyn = fyn;
    }

    public TCPFlags(boolean[]flags){
        if (flags.length != 8){
            throw new IllegalArgumentException("Array must be of size 8");
        }else{
            this.cwr = flags[0];
            this.ece = flags[1];
            this.urg = flags[2];
            this.ack = flags[3];
            this.psh = flags[4];
            this.rst = flags[5];
            this.syn = flags[6];
            this.fyn = flags[7];
        }
    }

    @Override
    public String toString() {
        return String.format("[%s, %s, %s, %s, %s, %s, %s, %s]",
                cwr, ece,urg, ack, psh, rst, syn, fyn);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        TCPFlags tcpFlags = (TCPFlags) o;

        if (cwr != tcpFlags.cwr) return false;
        if (ece != tcpFlags.ece) return false;
        if (urg != tcpFlags.urg) return false;
        if (ack != tcpFlags.ack) return false;
        if (psh != tcpFlags.psh) return false;
        if (rst != tcpFlags.rst) return false;
        if (syn != tcpFlags.syn) return false;
        return fyn == tcpFlags.fyn;

    }

    @Override
    public int hashCode() {
        int result = (cwr ? 1 : 0);
        result = 31 * result + (ece ? 1 : 0);
        result = 31 * result + (urg ? 1 : 0);
        result = 31 * result + (ack ? 1 : 0);
        result = 31 * result + (psh ? 1 : 0);
        result = 31 * result + (rst ? 1 : 0);
        result = 31 * result + (syn ? 1 : 0);
        result = 31 * result + (fyn ? 1 : 0);
        return result;
    }

    public String details() {
        return "TCPFlags{" +
                "cwr=" + cwr +
                ", ece=" + ece +
                ", urg=" + urg +
                ", ack=" + ack +

                ", psh=" + psh +
                ", rst=" + rst +
                ", syn=" + syn +
                ", fyn=" + fyn +
                '}';
    }




}
