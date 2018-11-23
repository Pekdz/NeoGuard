package ca.uwaterloo.crysp.privacyguard.Plugin;

import android.content.Context;
import android.support.annotation.Nullable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;

import ca.uwaterloo.crysp.privacyguard.Application.Database.DatabaseHandler;
import ca.uwaterloo.crysp.privacyguard.Application.Database.PacketRecord;
import ca.uwaterloo.crysp.privacyguard.Application.Logger;
import ca.uwaterloo.crysp.privacyguard.Application.Network.ConnectionMetaData;
import ca.uwaterloo.crysp.privacyguard.Application.Network.L7Protocol;


public class DomainDetectionPlugin implements IPlugin {
    private final boolean DEBUG = true;
    private final String TAG = DomainDetectionPlugin.class.getSimpleName();
    private HashSet<String> commonFileSet;
    private DatabaseHandler db;
    private DGADetector analyser;

    @Override
    @Nullable
    public LeakReport handleRequest(String request, byte[] rawRequest, ConnectionMetaData metaData) {
        try {
            if (metaData.protocol == L7Protocol.HTTP) {
                ArrayList<LeakInstance> leaks = new ArrayList<>();

                if (metaData.currentPacket != null) {
                    PacketRecord httpReq = metaData.currentPacket;

                    String[] pathParts = httpReq.path.split("\\.");
                    if (httpReq.type.contains("GET")
                            && commonFileSet.contains(pathParts[pathParts.length - 1])) {
                        if (DEBUG) Logger.i(TAG, "HTTP-GET for common files, skip domain checking");
                        return null;
                    }

                    DGADetector.Result result = analyser.getResult(httpReq.domain);
                    if (DEBUG) {
                        Logger.i(TAG, "DGA Result => isDGA: " + result.isDGA + ", score: " + result.score);
                    }

                    if (result.isDGA || result.score <= analyser.getScoreThresh()) {
                        // check packet record isn't saved to database
                        if (metaData.currentPacket.dbId == -1) {
                            metaData.currentPacket = db.addPacketRecord(httpReq);
                        }
                        LeakInstance leak = new DomainInstance("Suspicious Domain", httpReq.domain,
                                httpReq.dbId, result.isDGA, result.score, httpReq.time);
                        leaks.add(leak);
                    }
                }

                if (leaks.isEmpty())
                    return null;

                LeakReport rpt = new LeakReport(LeakReport.LeakCategory.DOMAIN);
                rpt.addLeaks(leaks);
                return rpt;

            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public LeakReport handleResponse(String response) {
        return null;
    }

    @Override
    public String modifyRequest(String request) {
        return request;
    }

    @Override
    public String modifyResponse(String response) {
        return response;
    }

    @Override
    public void setContext(Context context) {
        db = DatabaseHandler.getInstance(context);
        analyser = DGADetector.getInstance();
        commonFileSet = new HashSet<>(Arrays.asList("js", "html", "css", "svg", "gif", "png", "jpg", "woff2"));
    }
}
