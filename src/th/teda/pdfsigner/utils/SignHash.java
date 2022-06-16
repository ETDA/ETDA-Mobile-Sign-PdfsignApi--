package th.teda.pdfsigner.utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.DefaultCMSSignatureEncryptionAlgorithmFinder;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;

public class SignHash {
	private static PrivateKey privateKey;
	private static Certificate certificate;
	private static Certificate[] certificateChain;

	public SignerInfo sign(String digestMessage) throws IOException {
		try {

			byte[] digestBytes = Base64.decode(digestMessage);

			List<Certificate> certList = new ArrayList<>();
			certList.addAll(Arrays.asList(certificateChain));
			org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate
					.getInstance(ASN1Primitive.fromByteArray(certificate.getEncoded()));

			ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
			signedAttributes.add(new Attribute(CMSAttributes.contentType,
					new DERSet(new ASN1ObjectIdentifier("1.2.840.113549.1.7.1"))));
			signedAttributes
					.add(new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(digestBytes))));

			// =========================== For LTV Enable ===========================
			List<CRL> crlList = new DssHelper().readCRLsFromCert((X509Certificate) certificate);
			CertificateList[] certRevList = new CertificateList[crlList.size()];

			for (int i = 0; i < crlList.size(); i++) {
				X509CRL crl = (X509CRL) crlList.get(0);
				X509CRLHolder crlHolder = new X509CRLHolder(crl.getEncoded());
				certRevList[i] = crlHolder.toASN1Structure();
			}

			List<OCSPResponse> ocspList = new ArrayList<OCSPResponse>();
			for (int i = 0; i < certificateChain.length; i++) {
				X509Certificate certTemp = (X509Certificate) certificateChain[i];
				if (!certTemp.getIssuerDN().equals(certTemp.getSubjectDN())) {

					X509Certificate issuerCert = (X509Certificate) certificateChain[i + 1];
					if (issuerCert == null) {
						issuerCert = new GetOcspResp().getIssuerCert(certTemp);
					}
					OCSPResp ocspResp = new GetOcspResp().getOcspResp(certTemp, issuerCert);
					if (ocspResp != null) {
						ocspList.add(OCSPResponse.getInstance(ocspResp.getEncoded()));
					}
				}
			}

			OCSPResponse[] ocsps = new OCSPResponse[ocspList.size()];
			for (int i = 0; i < ocspList.size(); i++) {
				ocsps[i] = ocspList.get(i);
			}

			RevocationValues revValues = new RevocationValues(certRevList, ocsps, null);

			signedAttributes
					.add(new Attribute(new ASN1ObjectIdentifier("1.2.840.113583.1.1.8"), new DERSet(revValues)));

			// =========================== For LTV Enable ===========================

			AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);
			signedAttributesTable.toASN1EncodableVector();
			DefaultSignedAttributeTableGenerator signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(
					signedAttributesTable);

			SignerInfoGeneratorBuilder signerInfoBuilder = new SignerInfoGeneratorBuilder(
					new JcaDigestCalculatorProviderBuilder().build());
			signerInfoBuilder.setSignedAttributeGenerator(signedAttributeGenerator);

			ContentSigner sha512Signer = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);

			SignerInfoGenerator signerInfoGen = signerInfoBuilder.build(sha512Signer, new X509CertificateHolder(cert));

			X509CertificateHolder certHolder = new X509CertificateHolder(cert);
			DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
			AlgorithmIdentifier digesterAlgId = digAlgFinder.find(sha512Signer.getAlgorithmIdentifier());
			DigestCalculatorProvider digesterProv = new JcaDigestCalculatorProviderBuilder().build();
			DefaultCMSSignatureEncryptionAlgorithmFinder sigEncAlgFinder = new DefaultCMSSignatureEncryptionAlgorithmFinder();
			AlgorithmIdentifier digestEncryptAl = sigEncAlgFinder
					.findEncryptionAlgorithm(sha512Signer.getAlgorithmIdentifier());

			Map parameters = getBaseParameters(new ASN1ObjectIdentifier("1.2.840.113549.1.7.1"), digesterAlgId,
					digestEncryptAl, digesterProv.get(digesterAlgId).getDigest());
			AttributeTable signed = signedAttributeGenerator.getAttributes(Collections.unmodifiableMap(parameters));

			ASN1Set signedAttr = getAttributeSet(signed);

			byte[] bytes = signedAttr.getEncoded(ASN1Encoding.DER);
			String temp = "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";
			byte[] bytes2 = Base64.decode(temp.getBytes());

			ASN1Set testASN = (ASN1Set) ASN1Set.fromByteArray(bytes2);

			String byteString = "Rz/Id1yV12/MCnXZ1/UZBjknyhPTknq868OH6bjtU30mhbOexHpa6qRuo9yh5A/yrSb5nzsvgISM+iG6v68mdlzansOnBDrhIy8Joc3ZkimDNdF/jInseX/S5icNYVR9LHTyEnrVo5v5S+pbnmJO3NZKVmWg+PDlVx255v23EJyR61MBhfgy1nnnid64qcbMlLbJyN2l97k63QsBB9qmsvGRMhYfzQ4WLjfdgWZNvHIxnx7SvSoEHxQPZqHIGw+jfaeTQK4ONR4nw+E9lJUtJDb46zb+G9cJXR1YY9HGumxvyYCtOLLYpdzyu4I0nPDvGwT/sc4NHK9Hl5iE9vbyn9kX6FNpGo8MiDHTVQ8HuVQh9IdbvZxTQB3tdo3nh9xcNUs9Cgq9uv0NWxLRYZ0OObDvfcNuIcENH7iQ5WhVBq+cSBgTCuZwKbk1vRnWVE8gt65Z329+sBeiLS731ZVTnq2Ykjj5ALvBYOLvPPU9AayQvB1RV03m5+U1A1FRs7dcyZUAGZSzqBo9oQhbqxEyw5Xj+ln/yIc+eHzGxbcGHCs3itYrRpsocNtZDAAsDo1Emp+Ok7Xjelf1N/DwzuJI0ak7Y+T2qqtlCSI1cG7hU5ftsILCpnQhoC/bwOiuN6CRz6Yrq3+7dWJD1JU1YRsO/uWgC9HmWGRlN9MS60yAIcc=";
			byte[] sigBytes = Base64.decode(byteString);

//	        SignerInfo signerInfo =new SignerInfo(new SignerIdentifier(new IssuerAndSerialNumber(certHolder.toASN1Structure())), digesterAlgId,
//	        		testASN, digestEncryptAl, new DEROctetString(sigBytes), null);

//	        
			SignerInfo signerInfo = signerInfoGen.generate(new ASN1ObjectIdentifier("1.2.840.113549.1.7.1"));

			return signerInfo;
		} catch (Exception e) {
			// e.printStackTrace();
			// return null;
			throw new IOException(e);
		}
	}

	/**
	 * The signHash(String, String, String) method is used to sign messageDigest
	 * 
	 * @param passwordP12
	 * @param inputFileP12
	 * @param inputHash
	 * @return
	 * @throws IOException
	 * @throws GeneralSecurityException
	 * @throws SignatureException
	 */

	public String signMsgDigest(String passwordP12, String inputFileP12, String inputHash)
			throws IOException, GeneralSecurityException, SignatureException {
		char[] password = passwordP12.toCharArray();

		KeyStore keystore = KeyStore.getInstance("PKCS12");
		keystore.load(new FileInputStream(inputFileP12), password);

		Enumeration<String> aliases = keystore.aliases();
		while (aliases.hasMoreElements()) {
			String alias = (String) aliases.nextElement();
			privateKey = (PrivateKey) keystore.getKey(alias, password);
			certificate = keystore.getCertificate(alias);
			certificateChain = keystore.getCertificateChain(alias);
		}

		SignerInfo signerInfo = sign(inputHash);
		byte[] encoded = Base64.encode(signerInfo.getEncoded());

		return new String(encoded);
	}

	private Map getBaseParameters(ASN1ObjectIdentifier contentType, AlgorithmIdentifier digAlgId,
			AlgorithmIdentifier sigAlgId, byte[] hash) {
		Map param = new HashMap();

		if (contentType != null) {
			param.put(CMSAttributeTableGenerator.CONTENT_TYPE, contentType);
		}

		param.put(CMSAttributeTableGenerator.DIGEST_ALGORITHM_IDENTIFIER, digAlgId);
		param.put(CMSAttributeTableGenerator.SIGNATURE_ALGORITHM_IDENTIFIER, sigAlgId);
		param.put(CMSAttributeTableGenerator.DIGEST, org.bouncycastle.util.Arrays.clone(hash));

		return param;
	}

	private ASN1Set getAttributeSet(AttributeTable attr) {
		if (attr != null) {
			return new DERSet(attr.toASN1EncodableVector());
		}

		return null;
	}
}
