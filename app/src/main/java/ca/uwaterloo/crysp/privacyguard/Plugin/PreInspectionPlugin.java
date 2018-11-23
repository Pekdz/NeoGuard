package ca.uwaterloo.crysp.privacyguard.Plugin;

import android.content.Context;
import android.support.annotation.Nullable;

import java.net.URI;
import java.nio.charset.Charset;

import ca.uwaterloo.crysp.privacyguard.Application.Database.PacketRecord;
import ca.uwaterloo.crysp.privacyguard.Application.Logger;
import ca.uwaterloo.crysp.privacyguard.Application.Network.ConnectionMetaData;
import ca.uwaterloo.crysp.privacyguard.Application.Network.DPI;
import ca.uwaterloo.crysp.privacyguard.Application.Network.L7Protocol;
import rawhttp.core.RawHttpRequest;


public class PreInspectionPlugin implements IPlugin {
    private final static String TAG = PreInspectionPlugin.class.getSimpleName();
    private final boolean DEBUG = true;
    private DPI dpi;

    @Override
    @Nullable
    public LeakReport handleRequest(String request, byte[] rawRequest, ConnectionMetaData metaData) {
        try {
            if (metaData.protocol == L7Protocol.HTTP) {

                RawHttpRequest httpReq = dpi.parseHttpRequest(request);
                if (httpReq != null) {
                    URI uri = httpReq.getUri();

                    String payload = "Empty";
                    if (httpReq.getBody().isPresent())
                        payload = httpReq.getBody().get().decodeBodyToString(Charset.forName("UTF-8"));

                    metaData.currentPacket = new PacketRecord(uri.getAuthority(), metaData.destIP,
                            metaData.destPort, "HTTP - " + httpReq.getMethod(),
                            uri.getPath(), uri.getQuery(), uri.getFragment(), payload);

                    if (DEBUG) {
                        if (DEBUG) {
                            Logger.i(TAG,  metaData.appName + "\n====== HTTP Request ======"
                                    // + "\nURI => " + uri.toString()
                                    + "\nDomain => " + uri.getAuthority()
                                    + "\nPath => " + uri.getPath()
                                    + "\nQuery => " + uri.getQuery()
                                    //+ "\nFrag => " + uri.getFragment()
                                    //+ "\nUpgrade => " + httpReq.getHeaders().getFirst("Upgrade").toString()
                                    //+ "\nUserAgent => " + httpReq.getHeaders().getFirst("User-Agent").toString()
                                    + "\nBody => " + payload
                                    + "\n====================\n");
                        }
                    }
                }
            } else if (metaData.protocol == L7Protocol.WEBSOCKET && metaData.outgoing) {
                String wsPayload = dpi.getWebsocketPayload(rawRequest);
                if (wsPayload == null)
                    wsPayload = "Empty";
                metaData.currentPacket = new PacketRecord(metaData.destHostName, metaData.destIP,
                        metaData.destPort, "Websocket", null, null, null, wsPayload);

                if (DEBUG) {
                    Logger.i(TAG, metaData.appName + "\n===== WebSocket ======="
                            + "\nDomain => " + metaData.destHostName
                            + "\nBody => " + wsPayload
                            + "\n====================\n");
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
        dpi = DPI.getInstance();
    }
}
