package ca.uwaterloo.crysp.privacyguard.Application.Database;

import java.text.SimpleDateFormat;
import java.util.Date;

public class PacketRecord {
    public String domain;
    public String destIp;
    public int destPort;
    public String type; // HTTP-method or Websocket
    public String path;
    public String query;
    public String fragment;
    public String payload;
    public String time;

    public long dbId; // row id in database table

    public PacketRecord(String domain, String destIp, int destPort, String type,
                        String path, String query, String fragment, String payload) {
        this.domain = domain;
        this.destIp = destIp;
        this.destPort = destPort;
        this.type = type;
        this.path = path;
        this.query = query;
        this.fragment = fragment;
        this.payload = payload;
        SimpleDateFormat formatter = new SimpleDateFormat("MM/dd HH:mm:ss");
        this.time = formatter.format(new Date());
    }

    public PacketRecord(String domain, String destIp, int destPort, String type,
                        String path, String query, String fragment, String payload, String time) {
        this.domain = domain;
        this.destIp = destIp;
        this.destPort = destPort;
        this.type = type;
        this.path = path;
        this.query = query;
        this.fragment = fragment;
        this.payload = payload;
        this.time = time;
    }

    @Override
    public String toString() {
        return "PacketRecord{" +
                "domain='" + domain + '\'' +
                ", destIp='" + destIp + '\'' +
                ", destPort=" + destPort +
                ", type='" + type + '\'' +
                ", path='" + path + '\'' +
                ", query='" + query + '\'' +
                ", fragment='" + fragment + '\'' +
                ", payload='" + payload + '\'' +
                ", time='" + time + '\'' +
                ", dbId=" + dbId +
                '}';
    }
}
