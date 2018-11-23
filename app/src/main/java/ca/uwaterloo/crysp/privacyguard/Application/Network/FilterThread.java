package ca.uwaterloo.crysp.privacyguard.Application.Network;

import ca.uwaterloo.crysp.privacyguard.Application.Logger;
import ca.uwaterloo.crysp.privacyguard.Plugin.IPlugin;
import ca.uwaterloo.crysp.privacyguard.Plugin.LeakReport;
import ca.uwaterloo.crysp.privacyguard.Application.Network.FakeVPN.MyVpnService;
import ca.uwaterloo.crysp.privacyguard.Application.Network.ConnectionMetaData;
import ca.uwaterloo.crysp.privacyguard.Plugin.TrafficRecord;
import ca.uwaterloo.crysp.privacyguard.Plugin.TrafficReport;

import java.util.concurrent.LinkedBlockingQueue;

public class FilterThread extends Thread {
    private static final String TAG = FilterThread.class.getSimpleName();
    private static final boolean DEBUG = false;
    private LinkedBlockingQueue<FilterMsg> toFilter = new LinkedBlockingQueue<>();
    private MyVpnService vpnService;
    ConnectionMetaData metaData;

    public FilterThread(MyVpnService vpnService) {
        this.vpnService= vpnService;
    }

    public FilterThread(MyVpnService vpnService, ConnectionMetaData metaData) {
        this.vpnService = vpnService;
        this.metaData = metaData;
    }

    public void offer(byte[] payload, ConnectionMetaData metaData) {
        FilterMsg filterData = new FilterMsg(payload, metaData);
        toFilter.offer(filterData);
    }

    public void filter(byte[] payload) {
        filter(payload, metaData);
    }

    public void filter(byte[] payload, ConnectionMetaData metaData) {
        String payloadStr = new String(payload);
        TrafficReport traffic;
        TrafficRecord record = vpnService.getTrafficRecord();
        traffic = record.handle(payloadStr);

        if(traffic != null){
            traffic.metaData = metaData;
            vpnService.addtotraffic(traffic);
        }
        // for each outgoing packet
        if(metaData.outgoing) {
            // reset for different plugin referenced packet
            metaData.currentPacket = null;

            // inspect by each plugin
            for (IPlugin plugin : vpnService.getNewPlugins()) {
                LeakReport leak = plugin.handleRequest(payloadStr, payload, metaData);
                if (leak != null) {
                    leak.metaData = metaData;
                    vpnService.notify(payloadStr, leak);
                    if (DEBUG) Logger.v(TAG, metaData.appName + " is leaking " + leak.category.name());
                    Logger.logLeak(leak.category.name());
                }
            }
        }
    }

    public void run() {
        try {
            while (!interrupted()) {
                FilterMsg temp = toFilter.take();
                filter(temp.payload, temp.metaData);
            }
        } catch (InterruptedException e) {
            //e.printStackTrace();
        }
    }

    class FilterMsg {
        ConnectionMetaData metaData;
        byte[] payload;

        FilterMsg(byte[] payload, ConnectionMetaData metaData) {
            this.payload = payload;
            this.metaData = metaData;
        }
    }
}
