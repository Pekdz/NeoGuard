package ca.uwaterloo.crysp.privacyguard.Application.Database;


public class CryptominerAlert extends ReportItem {
    private String domain;
    private String isPoolDomain;
    private String signatureName;

    public CryptominerAlert(String packageName, String appName, String category,
                            String domain, String isPoolDomain, String signatureName,
                            String timestamp, long refPacketId){
        this.packageName = packageName;
        this.appName = appName;
        this.category = category;
        this.domain = domain;
        this.isPoolDomain = isPoolDomain;
        this.signatureName = signatureName;
        this.timestamp = timestamp;
        this.refPacketId = refPacketId;
    }

    public String getDomain() {
        return domain;
    }

    public String getIsPoolDomain() {
        return isPoolDomain;
    }

    public String getSignatureName() {
        return signatureName;
    }
}
