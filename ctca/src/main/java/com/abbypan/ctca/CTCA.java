package com.abbypan.ctca;

import java.io.BufferedReader;
import java.io.File;
//import java.io.InputStream;
import java.io.InputStreamReader;
//import java.net.MalformedURLException;
import java.net.URL;
import java.net.URI;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
//import java.net.URLConnection;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
//import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.json.JSONArray;
//import org.apache.directory.shared.asn1.der.ASN1InputStream;
import org.json.JSONObject;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;

import com.google.common.net.InternetDomainName;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
//import oracle.security.crypto.cert.CRLDistPoint;

import org.apache.kerby.asn1.parse.Asn1ParseResult;
import org.apache.kerby.asn1.parse.Asn1Parser;
import org.apache.kerby.asn1.type.Asn1OctetString;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import org.openjdk.jmh.annotations.Mode;


@State(Scope.Benchmark)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@BenchmarkMode(Mode.All)
public class CTCA {
	

 public static void main(String[] args) throws Exception
 {   
	 CTCA ctca = new CTCA(); 

     String para[] = Arrays.copyOfRange(args, 0, 2); 
     if(args.length==2) {
    	 File cache_file = new File(args[2]);
    	 String ctca_cache_f =	 cache_file.getAbsolutePath();
    	 String ctca_content = new String(Files.readAllBytes(Paths.get(ctca_cache_f)));
    	 para[2] = ctca_content;
     }

	 HttpsURLConnection con = ctca.create_main_conn(para);
	 String res = ctca.get_content(con);
	 System.out.println(res+"\n");
 }   

	@Benchmark
	@Threads(value = 3)
    @Warmup(iterations = 3, time = 3, timeUnit = TimeUnit.SECONDS)
    @Fork(value = 1)
    @Measurement(iterations = 1000, time = 3 , timeUnit = TimeUnit.SECONDS)
	public static void benchmarkCTCA() throws Exception {
		  String[] para = { "https://www.boc.cn", "ctca", "{\"attid\":\"example\",\"content\":[{\"cadom\":[\"globalsign.com\",\"! letsencrypt.org\"],\"dom\":[\"www.cmbc.com.cn\",\"*.baidu.com\"]},{\"cadom\":[\"cfca.com.cn\",\"! letsencrypt.org\"],\"dom\":[\"www.psbc.com\",\"www.hxb.com.cn\",\"www.cebbank.com\"]},{\"cadom\":[\"digicert.cn\",\"digicert.com\",\"digicert-cn.com\",\"! letsencrypt.org\"],\"dom\":[\"www.spdb.com.cn\",\"www.icbc.com.cn\",\"www.citicbank.com\",\"www.cib.com.cn\",\"www.cgbchina.com.cn\",\"www.ccb.com\",\"www.boc.cn\",\"www.bankcomm.com\",\"www.abchina.com\",\"cmbchina.com\",\"bank.pingan.com\",\"*.alipay.com\"]},{\"dom\":[\"www.alipay.com\"],\"pkdgst\":[\"51f3f3f9cbaf62fadadd2593833daf09540f805488ae3ffd1f73505c7a6ca1f9\"]}],\"dgstalg\":\"SHA256\",\"time\":\"2024-07-25 15:00:00\"}"};
		  HttpsURLConnection con = create_main_conn(para);
		  String res = get_content(con);
	} 

	@Benchmark
	@Threads(value = 3)
    @Warmup(iterations = 3, time = 3, timeUnit = TimeUnit.SECONDS)
    @Fork(value = 1)
    @Measurement(iterations = 1000, time = 3 , timeUnit = TimeUnit.SECONDS)
	public static void benchmarkDefault() throws Exception {
		  String[] para = { "https://www.boc.cn", "default", "{\"attid\":\"example\",\"content\":[{\"cadom\":[\"globalsign.com\",\"! letsencrypt.org\"],\"dom\":[\"www.cmbc.com.cn\",\"*.baidu.com\"]},{\"cadom\":[\"cfca.com.cn\",\"! letsencrypt.org\"],\"dom\":[\"www.psbc.com\",\"www.hxb.com.cn\",\"www.cebbank.com\"]},{\"cadom\":[\"digicert.cn\",\"digicert.com\",\"digicert-cn.com\",\"! letsencrypt.org\"],\"dom\":[\"www.spdb.com.cn\",\"www.icbc.com.cn\",\"www.citicbank.com\",\"www.cib.com.cn\",\"www.cgbchina.com.cn\",\"www.ccb.com\",\"www.boc.cn\",\"www.bankcomm.com\",\"www.abchina.com\",\"cmbchina.com\",\"bank.pingan.com\",\"*.alipay.com\"]},{\"dom\":[\"www.alipay.com\"],\"pkdgst\":[\"51f3f3f9cbaf62fadadd2593833daf09540f805488ae3ffd1f73505c7a6ca1f9\"]}],\"dgstalg\":\"SHA256\",\"time\":\"2024-07-25 15:00:00\"}"}; 
		  HttpsURLConnection con = create_main_conn(para);
		  String res = get_content(con);
	} 
 
 public static HttpsURLConnection create_main_conn(String[] para) throws Exception {
	 HttpsURLConnection con=null;

	 if(para[1].equals("default")) {
		 con = create_conn(para[0]);
	 }else if(para[1].equals("bypass")) {
		 con = create_bypass_conn(para[0]);
	 }else if(para[1].equals("ctca")) {
		 con = create_ctca_conn(para[0], para[2]);
	 }
	 return con;
 }

 private static HttpsURLConnection create_ctca_conn(String https_url, String ctca_cache_content) throws Exception {
	 //System.out.println("****** ctca ********"); 

	 JSONObject ctca_cache = new JSONObject(ctca_cache_content);
	 //System.out.println(ctca_cache);
	 
     HttpsURLConnection con = create_conn(https_url);
     
     URI u = new URI(https_url);
     String host = u.getHost().toLowerCase();
     //System.out.println(">>> host : " + host );

     SSLSocketFactory sslSocketFactory = createCTCASslSocketFactory(host, ctca_cache);
     con.setSSLSocketFactory(sslSocketFactory);

     return con;

 }
 
 private static HttpsURLConnection create_bypass_conn(String https_url) throws Exception {
	 //System.out.println("****** bypass ********"); 

     HttpsURLConnection con = create_conn(https_url);

     SSLSocketFactory sslSocketFactory = createBypassSslSocketFactory();
     con.setSSLSocketFactory(sslSocketFactory);

     HostnameVerifier hv = createBypassHostnameVerifier();
     con.setHostnameVerifier(hv);

     return con;
 }

 public static X509TrustManager get_default_trust_manager()  throws Exception {
     TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
     trustManagerFactory.init((KeyStore) null);

     X509TrustManager default_tm = null;
     for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
         if (trustManager instanceof X509TrustManager x509TrustManager) {
             default_tm = x509TrustManager;
             break;
         }
     }
     return default_tm;
 }

 public static String checkCrtAtt(String h, X509Certificate ee, JSONObject crtatt) throws Exception {
	//System.out.println(">>> visit host : " + h);

	String sca = read_ca_dom(ee);
	//System.out.println(">>> TLS server cert CA dom : " + sca);

	String dgstAlg = crtatt.getString("dgstalg");
	//System.out.println(">>> ctca dgst alg : " + dgstAlg);

	String spk = calc_subject_pk_dgst(dgstAlg, ee);
	//System.out.println(">>> TLS server cert dgst spk : " + spk);
		 
	JSONArray ct = crtatt.getJSONArray("content");

	JSONArray mcts = new JSONArray();
	JSONArray wcts = new JSONArray();
		 
	for (int i = 0; i < ct.length(); i++) {
		JSONObject ci = (JSONObject) ct.get(i);

		JSONArray dom = ci.getJSONArray("dom");
		for(int j=0;j<dom.length();j++) {
			String dj =  ((String) dom.get(j)).toLowerCase();

			if(dj.equals(h)) {
				mcts.put(ci);
				//System.out.println(">>> ctca find dom match: " + dj);
			}else if(dj.startsWith("*")) {
				String dje = dj.replaceFirst("^\\*", "");
				if(h.endsWith(dje)) {
					wcts.put(ci);
					//System.out.println(">>> ctca find wildcard dom match: " + dj);
				}
			}
		}
	}

	mcts.putAll(wcts);
	for(int i=0; i<mcts.length();i++) {
		JSONObject ci = (JSONObject) mcts.get(i);
		if( ! ci.isNull("cadom")) {
			JSONArray cadom = ci.getJSONArray("cadom");

			for(int j=0;j<cadom.length();j++) {
				String caj =  ((String) cadom.get(j)).toLowerCase();
				if(caj.equals(sca)) {
					//System.out.println(">>> ctca match sca: " + caj);
					return "success";
				}else if(caj.startsWith("!")) {
					String caje = caj.replaceFirst("^\\!\\s*", "");
					if(caje.equals(sca)) {
						//System.out.println(">>> ctca should not match sca: " + caj);
						return "fail";
					}
				}
			}
		}

		if( ! ci.isNull("pkdgst")) {
			JSONArray pkdgst = ci.getJSONArray("pkdgst");

			for(int j=0;j<pkdgst.length();j++) {
				String pkj =  ((String) pkdgst.get(j)).toLowerCase();
				if(pkj.equals(spk)) {
					//System.out.println(">>> ctca match pkdgst: " + pkj);
					return "success";
				}else if(pkj.startsWith("!")) {
					String pkje = pkj.replaceFirst("^\\!\\s*", "");
					if(pkje.equals(spk)) {
						//System.out.println(">>> ctca should not match pkdgst: " + pkj);
						return "fail";
					}
				}
			}
		}
	}

	return "unknown";
 }

 public static JSONObject read_ctca_cache(String fname) throws Exception {

	 String content = new String(Files.readAllBytes(Paths.get(fname)));
	 JSONObject jo = new JSONObject(content);


	 return jo;
 }

 public static String read_sld(String u) throws Exception {
	 URI uri = new URI(u);
	 String host = uri.getHost();

	 InternetDomainName internetDomainName = InternetDomainName.from(host).topPrivateDomain(); 
	 String domain = internetDomainName.toString().toLowerCase(); 

	 //    System.out.println(">>> url : " + u              );      
	 //   System.out.println(">>> host : " + host              );      
	 //  System.out.println(">>> domain : " + domain              );      

	 return domain;
 }

 public static String read_crl(X509Certificate ee) throws Exception {
	 byte[] crl = ee.getExtensionValue("2.5.29.31"); // CRL Distribution Points
	 //  System.out.println(">>> Cert CRL : " + new BigInteger(1, crl).toString(16)                 );      


	 Asn1OctetString octetString = new Asn1OctetString();           
	 for(int i=0; i<2; i++) {
		 octetString.decode(crl);
		 //   Asn1.dump(octetString);
		 crl = 	octetString.getValue();       
		 octetString.decode(crl);
	 }
	 //  Asn1.dump(octetString);


	 ByteBuffer buffer = ByteBuffer.wrap(octetString.getValue());
	 Asn1ParseResult res = Asn1Parser.parse(buffer);
	 byte[] crl_addr = res.readBodyBytes();
	 String crl_str =         new String(crl_addr , StandardCharsets.UTF_8);
	 //  System.out.println(">>> Cert CRL : " +        		crl_str        		);



	 //   ASN1InputStream  crlis = new ASN1InputStream(crl);
	 //com.hierynomus.asn1.types.constructed.ASN1Sequence s = crlis.iter;
	 // byte[] crlr = crlis.readValue(crlis.readLength());
	 //  ASN1Sequence  crlobj =  crlis.readObject();
	 //     System.out.println(" >>> crl der size : " + crlis.readObject());

	 //     ArrayList crlarr = (ArrayList) crlis.readObject().getValue();

	 //   ASN1OctetString  crl_asn1 = new ASN1OctetString(crl);
	 //    System.out.println(">>> Cert CRL : " +
	 //       		 new BigInteger(1, crl_asn1.getValueBytes()).toString(16)

	 // 		 new BigInteger(1, crl_asn1.getValue()).toString(16)
	 //	                      );   
	 // InputStream stream = new ByteArrayInputStream(exampleString.getBytes(StandardCharsets.UTF_8));
	 // InputStream stream = new ByteArrayInputStream(crl);

	 return crl_str;
 }

 public static String read_ca_dom(X509Certificate ee) throws Exception {
	 return read_sld(read_crl(ee));
 }

 public static byte[] read_subject_pk(X509Certificate ee) {
	 PublicKey pk = ee.getPublicKey();
	 //System.out.println(">>> Cert Public Key Algorithm : " + pk.getAlgorithm());

	 byte[] pk_der = pk.getEncoded();
	 //System.out.println(">>> Cert Public Key Algorithm : " + HexUtil.bytesToHex(pk_der) );

	 return pk_der;
 }

 public static byte[] digest( String hashName,  byte[] s) throws NoSuchAlgorithmException {
	 MessageDigest digest = MessageDigest.getInstance(hashName);
	 byte[] hash = digest.digest(s);
	 return hash;
 }

 public static String calc_subject_pk_dgst(String dgstAlg, X509Certificate ee) throws Exception {
	 byte[] pk_der = read_subject_pk(ee);
	 //  System.out.println(">>> Cert Public Key DER : " + HexFormat.of().formatHex(pk_der) );

	 byte[] dgst = digest(dgstAlg, pk_der);
	 String s =  HexFormat.of().formatHex(dgst);
	 //  System.out.println(">>> Cert Public Key Digest : " + s );

	 return s;
 }

 private static  SSLSocketFactory createCTCASslSocketFactory(String host, JSONObject ctca_cache) throws Exception {
	 X509TrustManager default_tm = get_default_trust_manager();

	 TrustManager[] ctcaTrustManagers = new TrustManager[] { new X509TrustManager() {

		 public X509Certificate[] getAcceptedIssuers() {
			 return default_tm.getAcceptedIssuers();
		 }

		 public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			 default_tm.checkServerTrusted(chain, authType);

			 X509Certificate ee = chain[0];

			 try {
				 String res = CTCA.checkCrtAtt(host, ee, ctca_cache);
				 if(res.equals("fail")) {
					 throw new Exception("CTCA check: fail!");
				 }
			 } catch (Exception e) {
				 e.printStackTrace();
			 }
		 }
		 public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			 default_tm.checkClientTrusted(chain, authType);
		 }
	 }

	 };

	 SSLContext sslContext = SSLContext.getInstance("TLS");
	 sslContext.init(null, ctcaTrustManagers, new SecureRandom());
	 return sslContext.getSocketFactory();
 }

 private static HostnameVerifier createBypassHostnameVerifier() {
	 HostnameVerifier hv = new HostnameVerifier() {
		 public boolean verify(String hostname, SSLSession session) { return true; }
	 };
	 return hv;
 }

 public static SSLSocketFactory createBypassSslSocketFactory() throws Exception {
	 TrustManager[] byPassTrustManagers = new TrustManager[] { new X509TrustManager() {
		 public X509Certificate[] getAcceptedIssuers() {
			 return new X509Certificate[0];
		 }
		 public void checkClientTrusted(X509Certificate[] chain, String authType) {
		 }
		 public void checkServerTrusted(X509Certificate[] chain, String authType) {
		 }
	 } };

	 SSLContext sslContext = SSLContext.getInstance("TLS");
	 sslContext.init(null, byPassTrustManagers, new SecureRandom());
	 return sslContext.getSocketFactory();
 }

 private static HttpsURLConnection create_conn(String https_url) throws Exception {

	 URL url;
	 url = URI.create(https_url).toURL();
	 HttpsURLConnection con = (HttpsURLConnection)url.openConnection();

	 return con;
 }



 private void print_https_cert(HttpsURLConnection con) throws Exception {

	 System.out.println("Response Code : " + con.getResponseCode());
	 System.out.println("Cipher Suite : " + con.getCipherSuite());
	 System.out.println("\n");



	 Certificate[] certs = con.getServerCertificates();
	 for(Certificate cert : certs){
		 System.out.println("Cert Type : " + cert.getType());
		 System.out.println("Cert Hash Code : " + cert.hashCode());
		 System.out.println("Cert Public Key Algorithm : "
				 + cert.getPublicKey().getAlgorithm());
		 System.out.println("Cert Public Key Format : "
				 + cert.getPublicKey().getFormat());

		 //String issuer = cert.getIssuerX500Principal().toString();
		 //System.out.println("Cert Issuer Name: " + issuer);

		 System.out.println("\n");
	 }

 }

 private static String get_content(HttpsURLConnection con) throws Exception {

	 //System.out.println("****** Content of the URL ********"); 
	 BufferedReader br =
			 new BufferedReader(
					 new InputStreamReader(con.getInputStream()));

	 String input;
	 String res = "";
	 while ((input = br.readLine()) != null){
		 res = res + input;      
		 //System.out.println(input);
	 }
	 br.close();

	 //System.out.println("\n");
	 
	 return res;
 }

}

