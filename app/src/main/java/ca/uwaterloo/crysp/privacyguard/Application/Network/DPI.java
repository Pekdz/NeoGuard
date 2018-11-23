package ca.uwaterloo.crysp.privacyguard.Application.Network;

import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Formatter;
import java.util.HashSet;
import java.util.Arrays;
import java.nio.ByteBuffer;
import java.util.List;

import org.java_websocket.drafts.Draft_6455;
import org.java_websocket.exceptions.*;
import org.java_websocket.framing.Framedata;

import ca.uwaterloo.crysp.privacyguard.Application.Logger;
import rawhttp.core.*;
import rawhttp.core.errors.InvalidHttpRequest;

public class DPI {
    private final boolean DEBUG = false;
    private final String TAG = DPI.class.getSimpleName();
    private static DPI instance;
    private HashSet<String> HTTPMethod = new HashSet<>(Arrays.asList("GET", "POST", "PUT", "HEAD", "CONNECT", "DELETE", "OPTIONS"));
    private RawHttp http;
    private Draft_6455 wsHelper;

    private DPI() {
        http = new RawHttp();
        wsHelper = new Draft_6455();
    }

    public static DPI getInstance() {
        if (instance == null) {
            instance = new DPI();
        }
        return instance;
    }

    public L7Protocol getProtocol(ConnectionMetaData metaData, String payload) {
        if (isHttpReq(payload)) {
            if (isWebSocketHS(payload))
                return L7Protocol.WEBSOCKET;
            else
                return L7Protocol.HTTP;
        } else if (metaData.destPort == 53)
            return L7Protocol.DNS;
        else
            return L7Protocol.OTHER;
    }

    public RawHttpRequest parseHttpRequest(String request) {
        try {
            if (isHttpReq(request)) {
                return http.parseRequest(request);
            }
        } catch (InvalidHttpRequest e) {
            if (DEBUG) Logger.w(TAG, "Parse http request failed: " + e.toString());
        }
        return null;
    }

    public String getWebsocketPayload(byte[] rawRequest) {
        try {
            Framedata frame = wsHelper.translateSingleFrame(ByteBuffer.wrap(rawRequest));
            return StandardCharsets.UTF_8.decode(frame.getPayloadData()).toString();
        } catch (Exception e) {
            Log.d(TAG, "Not supported websocket packet format.");
        } catch (IncompleteException e) {
            Log.w(TAG, "Websocket packet is incomplete.");
        }
        return null;
    }

    private void printHexData(byte[] data, String name) {
        Formatter formatter = new Formatter();
        for (byte b : data) {
            formatter.format("%02x", b);
        }
        Logger.d(TAG, name + ": " + formatter.toString() + "\n");
    }

    private byte[] convertToByteString(Object object) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream(); ObjectOutput out = new ObjectOutputStream(bos)) {
            out.writeObject(object);
            return bos.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private boolean isHttpReq(String payload) {
        if (payload == null || payload.isEmpty()) {
            return false;
        }
        String firstWord = payload.trim().split("\n")[0].split(" ")[0];
        return HTTPMethod.contains(firstWord);
    }

    private boolean isWebSocketHS(String payload) {
        RawHttpRequest request = http.parseRequest(payload);
        List<String> upgrade = request.getHeaders().get("Upgrade");
        return !upgrade.isEmpty() && upgrade.contains("websocket");
    }
}


