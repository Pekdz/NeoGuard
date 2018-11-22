package ca.uwaterloo.crysp.privacyguard.Plugin;

public class CryptominerInstance extends LeakInstance {
    public long refPacketId;
    public boolean isPoolDomain;
    public String signatureName;
    public String time;

    public CryptominerInstance(String type, String content, long refPacketId,
                               boolean isPoolDomain, String signatureName, String time) {
        super(type, content);

        this.refPacketId = refPacketId;
        this.isPoolDomain = isPoolDomain;
        this.signatureName = signatureName;
        this.time = time;
    }
}
