package es.vicboma1.utils.ssl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.security.cert.X509Certificate;

/**
 * @Author vicboma1
 * Clase que actua como mock para el SSL del war generado
 * Hace una validación con un certificado vacío y evita errores de fuentes externas no certificadas y desalineadas con el cacerts provenientes del server
 */
import java.security.SecureRandom;

    public class SSLUtils {

        private static final Logger LOGGER = LoggerFactory.getLogger(SSLUtils.class);

        public static void disableCertificateValidation() {

            try {

                final SSLContext sc = SSLContext.getInstance("SSL");
                sc.init(null,
                        new TrustManager[] {
                            new X509TrustManager() {
                                public X509Certificate[] getAcceptedIssuers() {
                                    final X509Certificate[] x509Certificates = new X509Certificate[0];
                                    LOGGER.info("getAcceptedIssuers -> new X509Certificate[0]=["+x509Certificates+"]");
                                    return x509Certificates;
                                }
                                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                                    for (X509Certificate x : certs) {
                                        LOGGER.info("****** checkClientTrusted ********* chain=[" + x.toString() + "]");
                                    }
                                    LOGGER.info("******* checkClientTrusted ******** authType=[" + authType + "]");
                                }
                                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                                    for (X509Certificate x : certs) {
                                        LOGGER.info("****** checkServerTrusted ********* chain=[" + x.toString() + "]");
                                    }
                                    LOGGER.info("******* checkServerTrusted ******** authType=[" + authType + "]");
                                }
                            }
                        }, new SecureRandom());

                //Evita el manejo del protocolo SSL
                HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
                //Evita fallos con fuentes externas o de otros dominios
                HttpsURLConnection.setDefaultHostnameVerifier(( hostname,  session) -> {
                    LOGGER.info(" ***** verify ****** hostname=["+hostname+"], session=["+session+"]");
                    return true;
                });
            } catch (Exception e) {
                LOGGER.error("disableCertificateValidation =>",e);
            }
        }
    }
