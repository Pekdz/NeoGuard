package ca.uwaterloo.crysp.privacyguard.Application.Database;


public class DomainAlert extends ReportItem {
    private String domain;
    private String isDGA;
    private String reputationScore;

    public DomainAlert(String packageName, String appName, String category,
                       String domain, String isDGA, String reputationScore,
                       String timestamp, long refPacketId){
        this.packageName = packageName;
        this.appName = appName;
        this.category = category;
        this.domain = domain;
        this.isDGA = isDGA;
        this.reputationScore = reputationScore;
        this.timestamp = timestamp;
        this.refPacketId = refPacketId;
    }

    public String getDomain() {
        return domain;
    }

    public String isDGA() {
        return isDGA;
    }

    public String getReputationScore() {
        return reputationScore;
    }
}
