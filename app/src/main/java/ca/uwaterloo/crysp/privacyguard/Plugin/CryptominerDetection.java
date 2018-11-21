package ca.uwaterloo.crysp.privacyguard.Plugin;

import android.content.Context;
import android.support.annotation.Nullable;

import java.util.ArrayList;

import ca.uwaterloo.crysp.privacyguard.Application.Database.DatabaseHandler;
import ca.uwaterloo.crysp.privacyguard.Application.Database.PacketRecord;
import ca.uwaterloo.crysp.privacyguard.Application.Logger;
import ca.uwaterloo.crysp.privacyguard.Application.Network.ConnectionMetaData;
import ca.uwaterloo.crysp.privacyguard.Application.Network.DPI;
import ca.uwaterloo.crysp.privacyguard.Application.Network.L7Protocol;


public class CryptominerDetection implements IPlugin {
    private final boolean DEBUG = true;
    private final String TAG = CryptominerDetection.class.getSimpleName();
    DatabaseHandler db;
    DPI dpi;

    @Override
    @Nullable
    public LeakReport handleRequest(String request, byte[] rawRequest, ConnectionMetaData metaData) {
        try {
            if (metaData.protocol == L7Protocol.WEBSOCKET && metaData.outgoing) {
                ArrayList<LeakInstance> leaks = new ArrayList<>();
                String wsPayload= dpi.getWebsocketPayload(rawRequest);
                if (DEBUG)  {
                    Logger.i(TAG, metaData.appName + " ===== WebSocket ======="
                            + "\nDomain => " + metaData.destHostName
                            + "\nPayload => \n" + wsPayload
                            + "\n ===========");
                }

                // TODO: check for cyptominer
                boolean domainIsMiningPool = true;
                String signatureName = "N/A";

                if (domainIsMiningPool || !signatureName.equals("N/A")) {
                    // check packet record isn't saved to database
                    if (metaData.currentPacket == null) {
                        metaData.currentPacket = db.addPacketRecord(new PacketRecord(metaData.destHostName,
                                metaData.destIP, metaData.destPort, "Websocket",
                               null, null, null, wsPayload));
                    }

                    LeakInstance leak = new CryptominerInstance("Cyptominer detected", metaData.destHostName,
                            metaData.currentPacket.dbId, domainIsMiningPool, signatureName, metaData.currentPacket.time);
                    leaks.add(leak);
                }

                if (leaks.isEmpty())
                    return null;

                LeakReport rpt = new LeakReport(LeakReport.LeakCategory.CRYPTOMINER);
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
        dpi = DPI.getInstance();
    }
}
