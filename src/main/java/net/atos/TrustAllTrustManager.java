package net.atos;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


public class TrustAllTrustManager implements X509TrustManager {

  private static Logger LOG = LoggerFactory.getLogger(TrustAllTrustManager.class);

  @Override
  public void checkClientTrusted(X509Certificate[] x509Certificates, String authType) throws CertificateException {
//do nothing, trust all certificates
    logMessage(x509Certificates, authType);
  }

  @Override
  public void checkServerTrusted(X509Certificate[] x509Certificates, String authType) throws CertificateException {
//do nothing, trust all certificates
    logMessage(x509Certificates, authType);
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return new X509Certificate[0];
  }

  private void logMessage(X509Certificate[] x509Certificates, String authType) {
    StringBuilder message = new StringBuilder();
    String lineSeparator = System.getProperty("line.separator");
    message.append("Trusted following certificates for authentication type '").append(authType).append("'").append(lineSeparator);
    for (X509Certificate certificate : x509Certificates) {
      message.append(certificate).append(lineSeparator);
    }
    LOG.trace(message.toString());
  }
}
