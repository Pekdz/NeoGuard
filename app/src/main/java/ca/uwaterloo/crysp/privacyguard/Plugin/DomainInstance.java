package ca.uwaterloo.crysp.privacyguard.Plugin;

public class DomainInstance extends LeakInstance {
    public long refPacketId;
    public boolean isDGA;
    public double reputationScore;
    public String time;

    public DomainInstance(String type, String content,
                          long refPacketId, boolean isDGA, double reputationScore, String time) {
        super(type, content);

        this.refPacketId = refPacketId;
        this.isDGA = isDGA;
        this.reputationScore = reputationScore;
        this.time = time;
    }
}
