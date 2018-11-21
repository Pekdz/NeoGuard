package ca.uwaterloo.crysp.privacyguard.Plugin;


public class LeakInstance{
    public String type;
    public String content;
    public long refPacketId;

    public LeakInstance(String type, String content, long refPacketId){
        this.type = type;
        this.content = content;
        this.refPacketId = refPacketId;
    }
}
