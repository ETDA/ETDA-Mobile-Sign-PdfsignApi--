package th.teda.pdfsigner.services;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
//import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
//import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
//import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.client.HttpClient;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

import th.teda.pdfsigner.utils.GetOcspResp;
import th.teda.pdfsigner.utils.TSAClient;

/**
 * 
 * @author itsaya
 *
 */
public class CreateCMSSignedData implements SignatureInterface {
	private static TSAClient tsaClient;
	private static Certificate[] certificateChain;
	private static SignerInfo signerInfo;
	private static String keysPass;
	private static String keysPath;
	private static String keysType;
	private static URL tsaUrl;

	byte[] packPDF(byte[] inputBytes, Long time) throws IOException {
		PDDocument doc = null;
		try {
			doc = PDDocument.load(inputBytes);
			Long id = time;
			doc.setDocumentId(id);
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			PDSignature signature = new PDSignature();
			signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
			signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
//			signature.setSignDate(Calendar.getInstance());
			Calendar cal = Calendar.getInstance();
			Date date = new Date(time);

			cal.setTime(date);
			signature.setSignDate(cal);

			COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
			catalogDict.setNeedToBeUpdated(true);

			// For big certificate chain
			SignatureOptions signatureOptions = new SignatureOptions();
			signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 12);

			doc.addSignature(signature, this, signatureOptions);
			doc.saveIncremental(bos);
			byte[] outputBytes = bos.toByteArray();
			return outputBytes;
		} catch (Exception e) {
			// e.printStackTrace();
			// return false;
			throw e;

		} finally {
			if (doc != null) {
				doc.close();
			}
		}
	}

	@Override
	public byte[] sign(InputStream is) throws IOException {
		try {

			List<Certificate> certList = new ArrayList<>();
			certList.addAll(Arrays.asList(certificateChain));
			certList.removeAll(Collections.singleton(null));
//			if (certificateChain[2] == null) {
//
//				 //certList.addAll(Arrays.asList(certificateChain));
//				//for(int i = 0 ; i<certificateChain.length-1;i++ ) {
//				//certList.addAll(Arrays.asList(certificateChain[0]));}	
//				certList.removeAll(Collections.singleton(null));
//				
//			}
//			else {
//				certList.addAll(Arrays.asList(certificateChain));
//			}

			@SuppressWarnings("rawtypes")
			Store certStore = new JcaCertStore(certList);

			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

			gen.addCertificates(certStore);

			CMSProcessableInputStream msg = new CMSProcessableInputStream(is);
			CMSSignedData signedData = gen.generate(msg, false);

			MessageDigest md = MessageDigest.getInstance("SHA-256");
			CMSTypedData signedContent = signedData.getSignedContent();
			byte[] inputByteArray = IOUtils.toByteArray((InputStream) signedContent.getContent());
			byte[] digest = md.digest(inputByteArray);

			SignerInformation signerInformation = new SignerInformation(signerInfo,
					new ASN1ObjectIdentifier("1.2.840.113549.1.7.1"), msg, digest);

			SignerInformationStore signerInfos = new SignerInformationStore(signerInformation);

			signedData = CMSSignedData.replaceSigners(signedData, signerInfos);

			if (tsaClient != null)
				signedData = signTimeStamps(signedData);

			return signedData.getEncoded();
		} catch (Exception e) {
			// e.printStackTrace();
			// return null;
			throw new IOException(e);
		}
	}

	/**
	 * * The signWithTSA(String, String, String, String, String, String) method is
	 * used to sign PDF(.pdf) with TSA
	 * 
	 * @param encoded
	 * @param certString
	 * @param inputFileName
	 * @param outputFileName
	 * @param tsaUrl1          : the URL of the Time-Stamping Authority(TSA)
	 *                         service. you can use empty string("") or null if you
	 *                         don't have urlTsaClient, e.g. http://10.0.0.27/, "",
	 *                         null
	 * @param keystorePath     : path of input keystore file, e.g.
	 *                         C:/Users/keys/xxx.p12, abc.p12
	 * @param keystorePassword : password of keystore, e.g. 123, 5A754
	 * @param keystoreType
	 * @param time
	 * @throws Exception
	 */
	public static byte[] signWithTSA(String encoded, String[] certString, String inputFile,
			String tsaUrl1, String keystorePath, String keystorePassword, String keystoreType, Long time)
			throws Exception {

		// Convert base64 string to certificate
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		keysPath = keystorePath;
		keysPass = keystorePassword;
		keysType = keystoreType;

		certificateChain = new Certificate[certString.length + 1];
		for (int j = 0; j < certString.length; j++) {
			byte[] certEncoded = Base64.decode(certString[j].getBytes());
			ByteArrayInputStream inputStream = new ByteArrayInputStream(certEncoded);
			Certificate cert = fact.generateCertificate(inputStream);

			certificateChain[j] = cert;

			if (j == 1) {
				X509Certificate issCert = (X509Certificate) certificateChain[j];
				if (!issCert.getIssuerDN().equals(issCert.getSubjectDN())) {
					X509Certificate rootCert = new GetOcspResp().getIssuerCert(issCert);
					certificateChain[j + 1] = rootCert;
				}
			}
		}

		byte[] encodedSignerInfo = Base64.decode(encoded);

		ASN1Primitive signerPrimitive = ASN1Primitive.fromByteArray(encodedSignerInfo);
		signerInfo = SignerInfo.getInstance(signerPrimitive);

		if (!tsaUrl1.isEmpty() && tsaUrl1 != null) {

			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			tsaUrl = new URL(tsaUrl1);
			tsaClient = new TSAClient(tsaUrl, keystorePath, keystorePassword, keystoreType, digest);
		} else {
			tsaUrl = null;
			tsaClient = null;
		}

		//File inFile = new File(inputFileName);
		//File outFile = new File(outputFileName);
		byte[] inputBytes = java.util.Base64.getDecoder().decode(inputFile.getBytes(StandardCharsets.UTF_8));
		byte[] outputBytes = new CreateCMSSignedData().packPDF(inputBytes, time);
		return outputBytes;
	}

	private CMSSignedData signTimeStamps(CMSSignedData signedData)
			throws IOException, TSPException, UnrecoverableKeyException, KeyManagementException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException {
		SignerInformationStore signerStore = signedData.getSignerInfos();
		List<SignerInformation> newSigners = new ArrayList<>();

		for (SignerInformation signer : signerStore.getSigners()) {
			newSigners.add(signTimeStamp(signer));
		}

		// TODO do we have to return a new store?
		return CMSSignedData.replaceSigners(signedData, new SignerInformationStore(newSigners));
	}

	private SignerInformation signTimeStamp(SignerInformation signer)
			throws IOException, TSPException, UnrecoverableKeyException, KeyManagementException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException {
		AttributeTable unsignedAttributes = signer.getUnsignedAttributes();

		ASN1EncodableVector vector = new ASN1EncodableVector();
		if (unsignedAttributes != null) {
			vector = unsignedAttributes.toASN1EncodableVector();
		}

		byte[] token = tsaClient.getTimeStampToken(signer.getSignature());
		ASN1ObjectIdentifier oid = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;
		ASN1Encodable signatureTimeStamp = new Attribute(oid, new DERSet(ASN1Primitive.fromByteArray(token)));

		vector.add(signatureTimeStamp);
		Attributes signedAttributes = new Attributes(vector);

		SignerInformation newSigner = SignerInformation.replaceUnsignedAttributes(signer,
				new AttributeTable(signedAttributes));

		if (newSigner == null) {
			return signer;
		}

		return newSigner;
	}

	public static HttpClient getAllSSLClient()
			throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException, CertificateException,
			FileNotFoundException, IOException, UnrecoverableKeyException {

		TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {

			@Override
			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			@Override
			public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
			}

			@Override
			public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
			}
		} };

		SSLContext context = SSLContext.getInstance("SSL");
		if (keysType == "PKCS12") {
			KeyStore keystore = KeyStore.getInstance(keysType);
			// KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keystore.load(new FileInputStream(keysPath), keysPass.toCharArray()); // path

			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(keystore, keysPass.toCharArray());

			context.init(kmf.getKeyManagers(), trustAllCerts, null);
		} else {
			context.init(null, trustAllCerts, null);
		}
		HttpClientBuilder builder = HttpClientBuilder.create();

		HostnameVerifier allowAllHosts = new NoopHostnameVerifier();
		SSLConnectionSocketFactory sslConnectionFactory = new SSLConnectionSocketFactory(context, allowAllHosts);
		builder.setSSLSocketFactory(sslConnectionFactory);

		PlainConnectionSocketFactory plainConnectionSocketFactory = new PlainConnectionSocketFactory();
		Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
				.register("https", sslConnectionFactory).register("http", plainConnectionSocketFactory).build();

		HttpClientConnectionManager ccm = new BasicHttpClientConnectionManager(registry);

		builder.setConnectionManager(ccm);

		return builder.build();

	}
}