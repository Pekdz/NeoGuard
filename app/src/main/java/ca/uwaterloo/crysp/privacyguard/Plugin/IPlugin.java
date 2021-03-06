package ca.uwaterloo.crysp.privacyguard.Plugin;

import android.content.Context;

import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;

import java.io.IOException;

import ca.uwaterloo.crysp.privacyguard.Application.Network.ConnectionMetaData;

/**
 * Created by frank on 2014-06-23.
 */
public interface IPlugin {
    // May modify the content of the request and response
    public LeakReport handleRequest(String request, byte[] rawRequest, ConnectionMetaData metaData);
    public LeakReport handleResponse(String response);
    public String modifyRequest(String request);
    public String modifyResponse(String response);
    public void setContext(Context context);
}
