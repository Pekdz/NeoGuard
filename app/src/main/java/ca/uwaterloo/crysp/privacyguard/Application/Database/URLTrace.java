package ca.uwaterloo.crysp.privacyguard.Application.Database;

import java.text.ParseException;
import java.util.Date;

public class URLTrace extends ReportItem {
    private String url;
    private Date timestampDate;
    private String query;
    private String host;
    private String res;

    public URLTrace(String packageName, String appName, String category,
                    String url, String query, String host, String res, String timestamp){
        this.packageName = packageName;
        this.appName = appName;
        this.category = category;
        this.url = url;
        this.query = query;
        this.timestamp = timestamp;
        this.host = host;
        this.res = res;

        try {
            this.timestampDate = DatabaseHandler.getDateFormat().parse(timestamp);
        }
        catch (ParseException ex) {
            throw new RuntimeException("Invalid timestamp for URL trace, tried to parse: " + timestamp);
        }
    }

    public String getUrl() {
        return url;
    }

    public Date getTimestampDate() {
        return timestampDate;
    }

    public String getQuery() {
        return query;
    }

    public String getHost() {
        return host;
    }

    public String getRes() {
        return res;
    }
}
