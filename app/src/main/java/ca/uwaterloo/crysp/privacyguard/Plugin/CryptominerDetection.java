package ca.uwaterloo.crysp.privacyguard.Plugin;

import android.content.Context;
import android.support.annotation.Nullable;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import ca.uwaterloo.crysp.privacyguard.Application.Database.DatabaseHandler;
import ca.uwaterloo.crysp.privacyguard.Application.Database.PacketRecord;
import ca.uwaterloo.crysp.privacyguard.Application.Logger;
import ca.uwaterloo.crysp.privacyguard.Application.Network.ConnectionMetaData;
import ca.uwaterloo.crysp.privacyguard.Application.Network.DPI;
import ca.uwaterloo.crysp.privacyguard.Application.Network.L7Protocol;


public class CryptominerDetection implements IPlugin {
    private final boolean DEBUG = true;
    private final String TAG = CryptominerDetection.class.getSimpleName();
    private DatabaseHandler db;
    private DPI dpi;
    private HelperTool tool;

    @Override
    @Nullable
    public LeakReport handleRequest(String request, byte[] rawRequest, ConnectionMetaData metaData) {
        try {
            if (metaData.protocol == L7Protocol.WEBSOCKET && metaData.outgoing) {
                ArrayList<LeakInstance> leaks = new ArrayList<>();
                String wsPayload = dpi.getWebsocketPayload(rawRequest);
                if (DEBUG) {
                    Logger.i(TAG, metaData.appName + " ===== WebSocket ======="
                            + "\nDomain => " + metaData.destHostName
                            + "\nPayload => " + wsPayload
                            + "\n ===========");
                }

                // check for cyptominer
                boolean domainIsMiningPool = tool.isMiningPool(metaData.destHostName);
                String signatureName = tool.getSignature(wsPayload);

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
        tool = HelperTool.getInstance();
    }


    static class HelperTool {
        private List<String> urls = Arrays.asList("50btc.com", "abcpool.co", "alvarez.sfek.kz", "bitalo.com", "bitcoinpool.com",
                "bitminter.com", "mmpool.bitparking.com", "blisterpool.com", "btcguild.com", "btcmine.com", "btcmp.com",
                "btcmow.com", "btcwarp.com", "btcpoolman.com", "coinminers.co", "coinotron.com", "deepbit.net");
        private Set<String> MiningPoolUrls = new HashSet<>(urls);
        private static HelperTool instance;

        private HelperTool() {
        }

        public static HelperTool getInstance() {
            if (instance == null)
                instance = new HelperTool();
            return instance;
        }

        //detect url of mining pool
        public boolean isMiningPool(String domain) {
            return MiningPoolUrls.contains(domain);
        }

        public String getSignature(String payload) {
            String signature = "N/A";
            if (checkCoinHive((payload)))
                signature = "Coinhive";

            return signature;
        }

        //check coinhive websocket payload pattern
        private boolean checkCoinHive(String payload) {
            boolean hasBlob = false;
            boolean hasTarget = false;
            try {
                JSONObject ws_obj = new JSONObject(payload);
                Iterator<String> keys = ws_obj.keys();
                while (keys.hasNext()) {
                    String key = keys.next();
                    if (!hasBlob) hasBlob = key.equals("blob");
                    if (!hasTarget) hasTarget = key.equals("target");
                    if (hasBlob && hasTarget) return true;
                }
                return false;
            } catch (JSONException e) {
                // e.printStackTrace();
                return false;
            }
        }
    }
}

