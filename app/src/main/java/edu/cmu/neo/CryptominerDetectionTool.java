package edu.cmu.neo;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class CryptominerDetectionTool {
    private String domain;
    //private int portnumber;
    private String ws_payload;
    private List<String> urls = Arrays.asList("50btc.com", "abcpool.co", "alvarez.sfek.kz", "bitalo.com", "bitcoinpool.com",
            "bitminter.com", "mmpool.bitparking.com", "blisterpool.com", "btcguild.com", "btcmine.com", "btcmp.com",
            "btcmow.com", "btcwarp.com", "btcpoolman.com", "coinminers.co", "coinotron.com", "deepbit.net");
    private Set<String> MiningPoolUrls = new HashSet<>(urls);
    private static CryptominerDetectionTool instance;
    private CryptominerDetectionTool() {

    }
    public static CryptominerDetectionTool getInstance() {
        if (instance == null)
            instance = new CryptominerDetectionTool();
        return instance;
    }

    //detect url of mining pool
    public void setAppDomain(String domain) {
        this.domain = domain;
    }
    public boolean connectMiningPool() {
        return MiningPoolUrls.contains(domain);
    }

    //check coinhive websocket payload pattern
    public void setWsPayload(String payload) {
        this.ws_payload = payload;
    }
    public boolean checkCoinHive() {
        boolean hasBlob = false;
        boolean hasTarget = false;
        try {
            JSONObject ws_obj = new JSONObject(ws_payload);
            Iterator<String> keys = ws_obj.keys();
            while(keys.hasNext()) {
                String key = keys.next();
                if(!hasBlob)    hasBlob = key.equals("blob");
                if(!hasTarget) hasTarget = key.equals("target");
                if(hasBlob && hasTarget)   return true;
            }
            return false;
        } catch(JSONException e) {
            // e.printStackTrace();
            return false;
        }
    }
}
