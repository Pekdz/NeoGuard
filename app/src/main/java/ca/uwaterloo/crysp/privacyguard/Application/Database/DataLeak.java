package ca.uwaterloo.crysp.privacyguard.Application.Database;

import java.text.ParseException;
import java.util.Date;

public class DataLeak extends ReportItem {
    private String type;
    private String leakContent;
    private Date timestampDate;
    private int foregroundStatus;
    private String destination;

    public DataLeak(String packageName, String appName, String category, String type, String content, String timestamp, int foregroundStatus, String destination){
        this.packageName = packageName;
        this.appName = appName;
        this.category = category;
        this.type = type;
        this.leakContent = content;
        this.timestamp = timestamp;
        this.foregroundStatus = foregroundStatus;
        this.destination = destination;

        try {
            this.timestampDate = DatabaseHandler.getDateFormat().parse(timestamp);
        }
        catch (ParseException ex) {
            throw new RuntimeException("Invalid timestamp for DataLeak, tried to parse: " + timestamp);
        }
    }



    public String getType() {
        return type;
    }

    public String getLeakContent() {
        return leakContent;
    }

    public Date getTimestampDate() {
        return timestampDate;
    }

    public int getForegroundStatus() {
        return foregroundStatus;
    }

    public String getDestination() {
        return destination;
    }
}
