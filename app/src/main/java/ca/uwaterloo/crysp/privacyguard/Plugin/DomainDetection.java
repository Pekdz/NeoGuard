package ca.uwaterloo.crysp.privacyguard.Plugin;

import android.content.Context;
import android.support.annotation.Nullable;

import java.net.URI;
import java.nio.charset.Charset;
import java.util.ArrayList;

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
                    String payload = "";
                    if (httpReq.getBody().isPresent())
                        payload = httpReq.getBody().get().decodeBodyToString(Charset.forName("UTF-8"));

                    if (DEBUG) {
                        Logger.i(TAG, metaData.appName + " ===== HTTP Request ======\n "
                                + "Destination: " + metaData.destIP + ":" + metaData.destPort + "\n"
                                + httpReq.getStartLine().toString()
                                + "\nURI => " + uri.toString()
                                + "\nAuth => " + uri.getAuthority()
                                + "\nPath => " + uri.getPath()
                                //+ "\nQuery => " + uri.getQuery()
                                //+ "\nFrag => " + uri.getFragment()
                                //+ "\nUpgrade => " + httpReq.getHeaders().getFirst("Upgrade").toString()
                                //+ "\nUserAgent => " + httpReq.getHeaders().getFirst("User-Agent").toString()
                                + "\nBody => " + payload
                                + "\n===========\n");
                    }


                    // TODO: check domain reputation & DGA
                    boolean isDGA = true;
                    double reputationScore = 0.6;

                    if (isDGA) {
                        // check packet record isn't saved to database
                        if (metaData.currentPacket == null) {
                            metaData.currentPacket = db.addPacketRecord(new PacketRecord(uri.getAuthority(),
                                    metaData.destIP, metaData.destPort, "HTTP-" + httpReq.getMethod(),
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
    }
}
