/*
Copyright 2007 Srinivas Inguva

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of Stanford University nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

package ca.uwaterloo.crysp.privacyguard.Application.Network.MITMProxy;

import java.io.FileWriter;
import java.io.PrintWriter;

/**
 * Main class for the Man In The Middle SSL proxy.  Delegates the real work
 * to HTTPSProxyEngine.
 * 
 * NOTE: This code was originally developed as a project for use in the CS255 course at Stanford,
 * taught by Professor Dan Boneh.
 * 
 * @author Srinivas Inguva
 */

public class MITMProxyServer
{
    public static boolean debugFlag = false;

    public static void main(String[] args) {
	final MITMProxyServer proxy = new MITMProxyServer(args);
	proxy.run();
    }

    private Error printUsage() {
	System.err.println(
	    "\n" +
	    "Usage: " +
	    "\n java mitm.MITMProxyServer <options>" +
	    "\n" +
	    "\n Where options can include:" +
	    "\n" +
	    "\n   [-localHost <host name/ip>]  Default is localhost" +
	    "\n   [-localPort <port>]          Default is 8001" +
	    "\n   [-keyStore <file>]           Key store details for" +
	    "\n   [-keyStorePassword <pass>]   certificates. Equivalent to" +
	    "\n   [-keyStoreType <type>]       javax.net.ssl.XXX properties" +
	    "\n   [-keyStoreAlias <alias>]     Default is keytool default of 'mykey'" +
	    "\n   [-outputFile <filename>]     Default is stdout" +
	    "\n   [-v ]                        Verbose proxy output" +
	    "\n   [-h ]                        Print this message" +
	    "\n" +
	    "\n -outputFile specifies where the output from ProxyDataFilter will go." +
	    "\n By default, it is sent to stdout" +
	    "\n"
	    );

	System.exit(1);
	return null;
    }

    private Error printUsage(String s) {
	System.err.println("\n" + "Error: " + s);
	throw printUsage();
    }

    private ProxyEngine m_engine = null;

    private MITMProxyServer(String[] args)
    {
	// Default values.
	ProxyDataFilter requestFilter = new ProxyDataFilter();
	ProxyDataFilter responseFilter = new ProxyDataFilter();
	int localPort = 8001;
	String localHost = "localhost";

	int timeout = 0; 
	String filename = null;

	try {
	    for (int i=0; i<args.length; i++)
	    {
		if (args[i].equals("-localHost")) {
		    localHost = args[++i];
		} else if (args[i].equals("-localPort")) {
		    localPort = Integer.parseInt(args[++i]);
		} else if (args[i].equals("-keyStore")) {
		    System.setProperty(JSSEConstants.KEYSTORE_PROPERTY,
				       args[++i]);
		} else if (args[i].equals("-keyStorePassword")) {
		    System.setProperty(
			JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, args[++i]);
		} else if (args[i].equals("-keyStoreType")) {
		    System.setProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY,
				       args[++i]);
		} else if (args[i].equals("-keyStoreAlias")) {
		    System.setProperty(JSSEConstants.KEYSTORE_ALIAS_PROPERTY,
				       args[++i]);
		} else if (args[i].equals("-timeout")) {
		    timeout = Integer.parseInt(args[++i]) * 1000;
		} else if (args[i].equals("-v")) {
		    debugFlag = true;
		} else if (args[i].equals("-outputFile")) {
		    PrintWriter pw = new PrintWriter(new FileWriter(args[++i]), true);
		    requestFilter.setOutputPrintWriter(pw);
		    responseFilter.setOutputPrintWriter(pw);
		} else {
		    throw printUsage();
		}
	    }
	}
	catch (Exception e) {
	    throw printUsage();
	}

	if (timeout < 0) {
	    throw printUsage("Timeout must be non-negative");
	}

	final StringBuffer startMessage = new StringBuffer();

	startMessage.append("Initializing SSL proxy with the parameters:" +
	    "\n   Local host:       " + localHost + 
	    "\n   Local port:       " + localPort);
	startMessage.append("\n   (SSL setup could take a few seconds)");

	System.err.println(startMessage);

	try {
	    m_engine = 
		new HTTPSProxyEngine(new MITMPlainSocketFactory(),
				     new MITMSSLSocketFactory(),
				     requestFilter,
				     responseFilter,
				     localHost,
				     localPort,
				     timeout);
	    
	    System.err.println("Proxy initialized, listening on port " + localPort);
	}
	catch (Exception e){
	    System.err.println("Could not initialize proxy:");
	    e.printStackTrace();
	    System.exit(2);
	}
    }

    public void run() 
    {
	m_engine.run();
	System.err.println("Engine exited");
	System.exit(0);
    }
}
