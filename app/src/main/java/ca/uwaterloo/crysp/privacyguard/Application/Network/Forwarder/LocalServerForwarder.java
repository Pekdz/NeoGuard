/*
 * Modify the SocketForwarder of SandroproxyLib
 * Copyright (C) 2014  Yihang Song

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package ca.uwaterloo.crysp.privacyguard.Application.Network.Forwarder;

import ca.uwaterloo.crysp.privacyguard.Application.Database.DatabaseHandler;
import ca.uwaterloo.crysp.privacyguard.Application.Logger;
import ca.uwaterloo.crysp.privacyguard.Application.Network.ConnectionMetaData;
import ca.uwaterloo.crysp.privacyguard.Application.Network.DPI;
import ca.uwaterloo.crysp.privacyguard.Application.Network.FakeVPN.MyVpnService;
import ca.uwaterloo.crysp.privacyguard.Application.Network.FilterThread;
import ca.uwaterloo.crysp.privacyguard.Application.Network.FlowAnalyzer;
import ca.uwaterloo.crysp.privacyguard.Application.Network.FlowStats;
import ca.uwaterloo.crysp.privacyguard.Application.PrivacyGuard;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;

public class LocalServerForwarder extends Thread {

    private static final String TAG = LocalServerForwarder.class.getSimpleName();
    private static final boolean DEBUG = false;
    private static int LIMIT = 1368;

    private boolean outgoing = false;
    private MyVpnService vpnService;
    private InputStream in;
    private OutputStream out;
    private ConnectionMetaData metaData;
    private FlowStats flowStats;
    private DPI dpi;

    public LocalServerForwarder(Socket inSocket, Socket outSocket, boolean isOutgoing, MyVpnService vpnService, String packageName, String appName, FlowStats flowStats, boolean isPlain) {
        try {
            this.in = inSocket.getInputStream();
            this.out = outSocket.getOutputStream();
        } catch (IOException e) {
            e.printStackTrace();
        }
        this.outgoing = isOutgoing;
        this.vpnService = vpnService;
        this.flowStats = flowStats;
        this.dpi = DPI.getInstance();
        this.metaData = new ConnectionMetaData(packageName, appName, null, 0, null, 0, null, outgoing, isPlain);

        metaData.destIP = outSocket.getInetAddress().getHostAddress();
        metaData.destPort = outSocket.getPort();
        metaData.destHostName = outSocket.getInetAddress().getCanonicalHostName();
        metaData.srcIP = inSocket.getInetAddress().getHostAddress();
        metaData.srcPort = inSocket.getPort();
        metaData.encrypted = (isOutgoing && metaData.destPort == 443) || (!isOutgoing && metaData.srcPort == 443);

        setDaemon(true);
    }

    public static void connect(Socket clientSocket, Socket serverSocket, MyVpnService vpnService, String packageName, String appName, boolean isPlain) throws Exception {
        if (clientSocket != null && serverSocket != null && clientSocket.isConnected() && serverSocket.isConnected()) {
            clientSocket.setSoTimeout(0);
            serverSocket.setSoTimeout(0);

            FlowStats flowStats = new FlowStats();

            LocalServerForwarder clientServer = new LocalServerForwarder(clientSocket, serverSocket, true, vpnService, packageName, appName, flowStats, isPlain);
            LocalServerForwarder serverClient = new LocalServerForwarder(serverSocket, clientSocket, false, vpnService, packageName, appName, flowStats, isPlain);
            clientServer.start();
            serverClient.start();

            if (DEBUG) Logger.d(TAG, "Start forwarding for " + clientSocket.getInetAddress().getHostAddress()+ ":" + clientSocket.getPort() + "<->" + serverSocket.getInetAddress().getHostAddress() + ":" + serverSocket.getPort());
            while (clientServer.isAlive() && serverClient.isAlive()) {
                try {
                    Thread.sleep(10);
                    } catch (InterruptedException e) {
                }
            }
            if (DEBUG) Logger.d(TAG, "Stop forwarding " + clientSocket.getInetAddress().getHostAddress()+ ":" + clientSocket.getPort() + "<->" + serverSocket.getInetAddress().getHostAddress() + ":" + serverSocket.getPort());

            // TODO: End of a flow, can write flow statistics to database
            List<Double> paramList = flowStats.calculate();
            if (paramList != null) {
                boolean flowIsBad = FlowAnalyzer.getInstance().isBadFlow(paramList);
                Logger.i(TAG, flowStats.toString());
                // Logger.i(TAG, "Input params list => " + Arrays.toString(paramList.toArray()));
                Logger.i(TAG, "Flow is bad => " + flowIsBad);
                DatabaseHandler.getInstance(vpnService).updateAiFlowCnt(packageName, flowIsBad);
            }

            clientSocket.close();
            serverSocket.close();
            clientServer.join();
            serverClient.join();

        } else {
            if (DEBUG) Logger.d(TAG, "skipping socket forwarding because of invalid sockets");
            if (clientSocket != null && clientSocket.isConnected()) {
                clientSocket.close();
            }
            if (serverSocket != null && serverSocket.isConnected()) {
                serverSocket.close();
            }
        }
    }

    public void run() {

        FilterThread filterObject = null;
        if (!PrivacyGuard.asynchronous) filterObject = new FilterThread(vpnService, metaData);

        try {
            byte[] buff = new byte[LIMIT];
            int got;
            while ((got = in.read(buff)) > -1) {
                // TODO: mod flow statistics
                if (outgoing)
                    flowStats.addFwdPkt(got);
                else
                    flowStats.addBackPkt(got);

                if (PrivacyGuard.doFilter && metaData.isPlain) {
                    byte[] payload = Arrays.copyOf(buff, got);

                    // check protocol of flow
                    if (metaData.protocol == null) {
                        metaData.protocol = dpi.getProtocol(metaData, new String(buff, 0, got));
                    }

                    if (PrivacyGuard.asynchronous) {
                        vpnService.getFilterThread().offer(payload, metaData);
                    } else {
                        filterObject.filter(payload);
                    }
                }
                if (DEBUG) Logger.d(TAG, got + " bytes to be written to " + metaData.srcIP + ":" + metaData.srcPort + "->" + metaData.destIP + ":" + metaData.destPort);
                out.write(buff, 0, got);
                if (DEBUG) Logger.d(TAG, got + " bytes written to " + metaData.srcIP + ":" + metaData.srcPort + "->" + metaData.destIP + ":" + metaData.destPort);
                out.flush();
            }
            if (DEBUG) Logger.d(TAG, "terminating " + metaData.srcIP + ":" + metaData.srcPort + "->" + metaData.destIP + ":" + metaData.destPort);
        } catch (Exception ignore) {
            // ignore.printStackTrace();
            if (DEBUG) Logger.d(TAG, "outgoing : " + outgoing);
            // can happen when app opens a connection and then terminates it right away so
            // this thread will start running only after a FIN has already been to the server
        }
    }

}
