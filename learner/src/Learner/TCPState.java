package Learner;

public class TCPState {

    private long seq, ack;

    // True after one side reset the connection. The next SYN then opens a
    // new connection and needs a new initial sequence number.
    private boolean needsNewIsn;

    public TCPState(long seq, long ack) {
        this.seq = seq;
        this.ack = ack;
    }

    public long getSeq() {
        return this.seq;
    }

    public long getAck() {
        return this.ack;
    }

    public void setSeq(long seq) {
        this.seq = seq;
    }

    public void setAck(long ack) {
        this.ack = ack;
    }

    public boolean needsNewIsn() {
        return this.needsNewIsn;
    }

    public void setNeedsNewIsn(boolean needsNewIsn) {
        this.needsNewIsn = needsNewIsn;
    }
}
