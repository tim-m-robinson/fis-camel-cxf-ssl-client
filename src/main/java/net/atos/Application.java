/**
 *  Copyright 2005-2016 Red Hat, Inc.
 *
 *  Red Hat licenses this file to you under the Apache License, version
 *  2.0 (the "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 *  implied.  See the License for the specific language governing
 *  permissions and limitations under the License.
 */
package net.atos;


import org.apache.camel.CamelContext;
import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.cxf.CxfEndpoint;
import org.apache.camel.component.cxf.CxfEndpointConfigurer;
import org.apache.camel.component.cxf.DataFormat;
import org.apache.camel.component.servlet.CamelHttpTransportServlet;
import org.apache.cxf.Bus;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.endpoint.Server;
import org.apache.cxf.frontend.AbstractWSDLBasedEndpointFactory;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import javax.inject.Inject;
import javax.net.ssl.*;
import javax.security.cert.CertificateException;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Objects;

/**
 * A spring-boot application that includes a Camel route builder to setup the Camel routes
 */
@SpringBootApplication
public class Application extends RouteBuilder {

    private final String HTTPS4 = "https4";

    @Inject
    private CamelContext ctx;

    private CxfEndpoint cxfEndpoint;

    private String rawXmlData =
          "<soapenv:Envelope " +
          "	xmlns:ns0=\"http://net.atos\" "+
          "	xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "+
          "	xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "+
          "	xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "+
          "   xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"> "+
          "	<soapenv:Header> "+

          "<wsse:Security> "+
          "<wsse:UsernameToken> "+
          "  <wsse:Username>alice</wsse:Username> "+
          "   <wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\">password</wsse:Password> "+
          "</wsse:UsernameToken> "+
          "</wsse:Security> "+

          "	</soapenv:Header> "+
          "	<soapenv:Body> "+
          "	<ns0:reverseOperation xmlns:ns0=\"http://net.atos\"> "+
          "     <arg0>hello</arg0> "+
          "	</ns0:reverseOperation> "+
          "	</soapenv:Body> "+
          "</soapenv:Envelope>";


    // must have a main method spring-boot can run
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    ServletRegistrationBean servletRegistrationBean() {
        ServletRegistrationBean servlet = new ServletRegistrationBean(
            new CamelHttpTransportServlet(), "/camel/*");
        servlet.setName("CamelServlet");
        return servlet;
    }

    @Override
    public void configure() throws Exception {
        registerSSLContextWithTrustStore();
        configureEndpoints();

        ctx.setStreamCaching(true);

        restConfiguration()
        	.component("servlet")
        	.dataFormatProperty("prettyPrint", "true")
        	.contextPath("/camel")
        	.apiContextPath("/api-doc")
            	.apiProperty("api.title", "User API").apiProperty("api.version", "1.0.0")
            	.apiProperty("cors", "true");
        
        rest("/ping").description("User REST service")
        	.consumes(MediaType.APPLICATION_JSON_VALUE)
        	.produces(MediaType.TEXT_PLAIN_VALUE)

	        .get().id("ping").description("heartbeat response")
	        	.to("direct:in");

    	
        from("direct:in").id("pong")
            .process((exchange) -> {
              Map headers = exchange.getIn().getHeaders();
              headers.values().removeIf(Objects::isNull);
            })
            .setHeader("SOAPAction")
                .constant("reverseAction")
            .setHeader("operationName")
                .constant("reverseOperation")
            .setHeader(Exchange.HTTP_METHOD)
                .constant("POST")
            .setBody()
                .constant(rawXmlData)
            .to(cxfEndpoint)
                .log(">>> ${body}");
    }

    private void configureEndpoints() {
      cxfEndpoint = new CxfEndpoint();
      cxfEndpoint.setCamelContext(ctx);
      cxfEndpoint.setAddress("https://localhost:8443/cxf/dummy");
      cxfEndpoint.setWsdlURL("https://localhost:8443/cxf/dummy?wsdl");
      cxfEndpoint.setPortName("{http://net.atos}dummyPort");
      cxfEndpoint.setServiceNameString("{http://net.atos}dummyService");
      cxfEndpoint.setDataFormat(DataFormat.RAW);

      Bus bus = cxfEndpoint.getBus();
      bus.setProperty("ws-security.username", "alice");
      bus.setProperty("ws-security.password", "password");

      /* SSL/TLS config for CXF
       *
       */
      cxfEndpoint.setCxfEndpointConfigurer(new CxfEndpointConfigurer() {
        @Override
        public void configure(AbstractWSDLBasedEndpointFactory factoryBean) {
          // do nothing
        }

        @Override
        public void configureClient(Client client) {
          HTTPConduit conduit = (HTTPConduit) client.getConduit();
          TLSClientParameters tlsParams = new TLSClientParameters();
          tlsParams.setDisableCNCheck(true);
          tlsParams.setUseHttpsURLConnectionDefaultSslSocketFactory(true);
          conduit.setTlsClientParameters(tlsParams);
        }

        @Override
        public void configureServer(Server server) {
          //do nothing
        }
      });

    }
/*
    static {
      //for localhost testing only
      javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
        new javax.net.ssl.HostnameVerifier(){
          @Override
          public boolean verify(String hostname,
                                javax.net.ssl.SSLSession sslSession) {
            return true;
          }
      });
    }
*/
    private void registerSSLContextWithTrustStore() throws Exception {
      String keystorePath = "/truststore.jks";
      String keystorePassword = "password";

      try (InputStream keystoreFile = getClass().getResourceAsStream(keystorePath);) {

        KeyStore truststore = KeyStore.getInstance("JKS");
        truststore.load(keystoreFile, keystorePassword.toCharArray());

        TrustManagerFactory trustFactory = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustFactory.init(truststore);

        SSLContext sslcontext = SSLContext.getInstance("TLS");
        sslcontext.init(null, trustFactory.getTrustManagers(), new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sslcontext.getSocketFactory());

      } catch (FileNotFoundException fnfe) {
        log.error("Unable to open " + keystorePath);
      } catch (IOException ioException) {
        log.error("IOException getting jks for route" + ioException.getMessage());
      } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
        log.error("NoSuchAlgorithmException getting jks for route" + noSuchAlgorithmException.getMessage());
      } catch (KeyStoreException keyStoreException) {
        log.error("KeyStoreException getting jks for route" + keyStoreException.getMessage());
      } catch (KeyManagementException keyManagementException) {
        log.error("KeyManagementException getting jks for route" + keyManagementException.getMessage());
      }
    }

}
