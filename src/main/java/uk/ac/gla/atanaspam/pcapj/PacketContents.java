package uk.ac.gla.atanaspam.pcapj;

import java.io.Serializable;
import java.util.Arrays;

/**
 * @author atanaspam
 * @version 0.1
 * @created 24/01/2016
 */
public class PacketContents implements Serializable{

    private static final long serialVersionUID = 0;

    private final byte[] data;

    public PacketContents(byte[] data) {
        if (data == null) {
            throw new NullPointerException();
        }
        this.data = data;
    }

    public byte[] getData(){
        return data;
    }

    @Override
    public boolean equals(Object other)
    {
        if (!(other instanceof PacketContents)) {
            return false;
        }
        return Arrays.equals(data, ((PacketContents)other).data);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(data);
    }
}
