package ca.uwaterloo.crysp.privacyguard.Application.Database;

public class ReportItem {
    String packageName;
    String appName;
    String category;
    String timestamp;

    public String getPackageName() {
        return packageName;
    }

    public String getAppName() {
        return appName;
    }

    public String getCategory() {
        return category;
    }

    public String getTimestamp() {
        return timestamp;
    }
}
