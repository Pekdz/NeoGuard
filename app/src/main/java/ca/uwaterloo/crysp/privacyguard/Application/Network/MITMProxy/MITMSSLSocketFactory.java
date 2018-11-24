//Based on SnifferSSLSocketFactory.java from The Grinder distribution.
// The Grinder distribution is available at http://grinder.sourceforge.net/
/*
Copyright 2007 Srinivas Inguva

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of Stanford University nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

package ca.uwaterloo.crysp.privacyguard.Application.Network.MITMProxy;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;


/**
 * MITMSSLSocketFactory is used to create SSL sockets.
 * <p>
 * This is needed because the javax.net.ssl socket factory classes don't
 * allow creation of factories with custom parameters.
 */
public final class MITMSSLSocketFactory implements MITMSocketFactory {
    final ServerSocketFactory m_serverSocketFactory;
    final SocketFactory m_clientSocketFactory;
    final SSLContext m_sslContext;

    public KeyStore ks = null;

    /*
     *
     * We can't install our own TrustManagerFactory without messing
     * with the security properties file. Hence we create our own
     * SSLContext and initialise it. Passing null as the keystore
     * parameter to SSLContext.init() results in a empty keystore
     * being used, as does passing the key manager array obtain from
     * keyManagerFactory.getInstance().getKeyManagers(). To pick up
     * the "default" keystore system properties, we have to read them
     * explicitly. UGLY, but necessary so we understand the expected
     * properties.
     *
     */

    /**
     * This constructor will create an SSL server socket factory
     * that is initialized with a fixed CA certificate
     */
    public MITMSSLSocketFactory()
            throws IOException, GeneralSecurityException {
        m_sslContext = SSLContext.getInstance("SSL");

        final KeyManagerFactory keyManagerFactory =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

        final String keyStoreFile = System.getProperty(JSSEConstants.KEYSTORE_PROPERTY);
        final char[] keyStorePassword = System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, "").toCharArray();
        final String keyStoreType = System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "jks");

        final KeyStore keyStore;

        if (keyStoreFile != null) {
            keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);

            this.ks = keyStore;
        } else {
            keyStore = null;
        }

        keyManagerFactory.init(keyStore, keyStorePassword);

        m_sslContext.init(keyManagerFactory.getKeyManagers(),
                new TrustManager[]{new TrustEveryone()},
                null);

        m_clientSocketFactory = m_sslContext.getSocketFactory();
        m_serverSocketFactory = m_sslContext.getServerSocketFactory();
    }

    /**
     * This constructor will create an SSL server socket factory
     * that is initialized with a forged server certificate
     * that is issued by the proxy "CA certificate".
     */
    public MITMSSLSocketFactory(String remoteCN, iaik.x509.X509Certificate remoteServerCert)
            throws Exception {
        m_sslContext = SSLContext.getInstance("SSL");

        final KeyManagerFactory keyManagerFactory =
                KeyManagerFactory.getInstance(
                        KeyManagerFactory.getDefaultAlgorithm());

        final String keyStoreFile =
                System.getProperty(JSSEConstants.KEYSTORE_PROPERTY);
        final char[] keyStorePassword =
                System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, "")
                        .toCharArray();
        final String keyStoreType =
                System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "jks");

        final KeyStore keyStore;

        assert keyStoreFile != null;

        keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);

        //Create new server certificate
        PrivateKey pk = (PrivateKey) keyStore.getKey(JSSEConstants.DEFAULT_ALIAS, keyStorePassword);

        iaik.x509.X509Certificate newCert = SignCert.forgeCert(keyStore, keyStorePassword, JSSEConstants.DEFAULT_ALIAS,
                remoteCN, remoteServerCert);

        KeyStore newKS = KeyStore.getInstance("jks");
        newKS.load(null, null);

        newKS.setKeyEntry(JSSEConstants.DEFAULT_ALIAS, pk, keyStorePassword, new Certificate[]{newCert});
        //

        keyManagerFactory.init(newKS, keyStorePassword);

        m_sslContext.init(keyManagerFactory.getKeyManagers(),
                new TrustManager[]{new TrustEveryone()},
                null);

        m_clientSocketFactory = m_sslContext.getSocketFactory();
        m_serverSocketFactory = m_sslContext.getServerSocketFactory();
    }

    public final ServerSocket createServerSocket(String localHost,
                                                 int localPort,
                                                 int timeout)
            throws IOException {
        final SSLServerSocket socket =
                (SSLServerSocket) m_serverSocketFactory.createServerSocket(
                        localPort, 50, InetAddress.getByName(localHost));

        socket.setSoTimeout(timeout);

        socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

        return socket;
    }

    public final Socket createClientSocket(String remoteHost, int remotePort)
            throws IOException {
        final SSLSocket socket =
                (SSLSocket) m_clientSocketFactory.createSocket(remoteHost,
                        remotePort);

        socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

        socket.startHandshake();

        return socket;
    }

    /**
     * We're carrying out a MITM attack, we don't care whether the cert
     * chains are trusted or not ;-)
     */
    private static class TrustEveryone implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain,
                                       String authenticationType) {
        }

        public void checkServerTrusted(X509Certificate[] chain,
                                       String authenticationType) {
        }

        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }
}
    
