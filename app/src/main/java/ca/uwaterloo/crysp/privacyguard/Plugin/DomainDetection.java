package ca.uwaterloo.crysp.privacyguard.Plugin;

import android.content.Context;
import android.support.annotation.Nullable;

import java.net.URI;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;

import ca.uwaterloo.crysp.privacyguard.Application.Database.DatabaseHandler;
import ca.uwaterloo.crysp.privacyguard.Application.Database.PacketRecord;
import ca.uwaterloo.crysp.privacyguard.Application.Logger;
import ca.uwaterloo.crysp.privacyguard.Application.Network.ConnectionMetaData;
import ca.uwaterloo.crysp.privacyguard.Application.Network.DPI;
import ca.uwaterloo.crysp.privacyguard.Application.Network.L7Protocol;
import rawhttp.core.RawHttpRequest;


public class DomainDetection implements IPlugin {
    private final boolean DEBUG = true;
    private final String TAG = DomainDetection.class.getSimpleName();
    private HashSet<String> commonFileSet;
    DatabaseHandler db;
    DPI dpi;

    @Override
    @Nullable
    public LeakReport handleRequest(String request, byte[] rawRequest, ConnectionMetaData metaData) {
        try {
            if (metaData.protocol == L7Protocol.HTTP) {
                ArrayList<LeakInstance> leaks = new ArrayList<>();

                RawHttpRequest httpReq = dpi.parseHttpRequest(request);
                if (httpReq != null) {
                    URI uri = httpReq.getUri();

                    String method = httpReq.getMethod();
                    String[] pathParts = uri.getPath().split("\\.");

                    if (method.equals("GET") && commonFileSet.contains(pathParts[pathParts.length - 1])) {
                        if (DEBUG)
                            Logger.i(TAG, "HTTP GET common files, ignore for domain checking.");
                        return null;
                    }

                    String payload = "";
                    if (httpReq.getBody().isPresent())
                        payload = httpReq.getBody().get().decodeBodyToString(Charset.forName("UTF-8"));

                    boolean isDGA = DGADetector.getInstance().isDGA(uri.getAuthority());
                    // TODO: check domain reputation
                    double reputationScore = 0;

                    if (DEBUG) {
                        Logger.i(TAG, metaData.appName + " ====== HTTP Request ======\n "
                                //+ "Destination: " + metaData.destIP + ":" + metaData.destPort + "\n"
                                + "\nURI => " + uri.toString()
                                //+ "\nAuth => " + uri.getAuthority()
                                //+ "\nPath => " + uri.getPath()
                                //+ "\nQuery => " + uri.getQuery()
                                //+ "\nFrag => " + uri.getFragment()
                                //+ "\nUpgrade => " + httpReq.getHeaders().getFirst("Upgrade").toString()
                                //+ "\nUserAgent => " + httpReq.getHeaders().getFirst("User-Agent").toString()
                                + "\nBody => " + payload
                                + "\nCheck Result => isDGA: " + isDGA + ", score: " + reputationScore
                                + "\n ====================\n");
                    }

                    if (isDGA || reputationScore > 0.6) {
                        // check packet record isn't saved to database
                        if (metaData.currentPacket == null) {
                            metaData.currentPacket = db.addPacketRecord(new PacketRecord(uri.getAuthority(),
                                    metaData.destIP, metaData.destPort, "HTTP - " + httpReq.getMethod(),
                                    uri.getPath(), uri.getQuery(), uri.getFragment(), payload));
                        }
                        LeakInstance leak = new DomainInstance("Suspicious Domain", uri.getAuthority(),
                                metaData.currentPacket.dbId, isDGA, reputationScore, metaData.currentPacket.time);
                        leaks.add(leak);
                    }
                }

                if (leaks.isEmpty())
                    return null;

                LeakReport rpt = new LeakReport(LeakReport.LeakCategory.DOMAIN);
                rpt.addLeaks(leaks);
                return rpt;

            } else if (metaData.protocol != L7Protocol.WEBSOCKET && metaData.outgoing) {
                if (DEBUG && (metaData.destPort == 443 || metaData.destPort == 80)) {
                    Logger.i(TAG, metaData.appName + " ===== Unknown Payload =======\n"
                            + "Destination: " + metaData.destIP + ":" + metaData.destPort + "\n"
                            + request + "\n===========\n");
                }

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
        dpi = DPI.getInstance();
        commonFileSet = new HashSet<>(Arrays.asList("js", "html", "css", "svg", "gif", "png", "jpg", "woff2"));
    }
}
