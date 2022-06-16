package th.teda.pdfsigner.services;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
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
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.DefaultCMSSignatureEncryptionAlgorithmFinder;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;

import th.teda.pdfsigner.utils.DssHelper;
import th.teda.pdfsigner.utils.GetOcspResp;
import th.teda.pdfsigner.utils.RevocationValues;

public class CreateSignedBytes {
	private Certificate certificate;
	private OCSPResp ocspResp;
	private List<CRL> crlList;
	//private PDFSigner signer;

	public String[] createSignedBytes(String digestMessage, String[] certString) throws Exception {
		byte[] digestBytes = Base64.decode(digestMessage);
		CertificateFactory fact;
		try {
			fact = CertificateFactory.getInstance("X.509");

			Certificate[] certificateChain = new Certificate[certString.length + 1];
			for (int j = 0; j < certString.length; j++) {

				String cer = certString[j];
				String chk_cert = cer.replace("#015", "");

				byte[] certEncoded = Base64.decode(chk_cert.getBytes());

				ByteArrayInputStream inputStream = new ByteArrayInputStream(certEncoded);
				Certificate cert;

				cert = fact.generateCertificate(inputStream);
				certificateChain[j] = cert;

				// get..root certificate
				if (j == 1) {

					X509Certificate issCert = (X509Certificate) certificateChain[j];
					if (!issCert.getIssuerDN().equals(issCert.getSubjectDN())) {
						X509Certificate rootCert = new GetOcspResp().getIssuerCert(issCert);
						certificateChain[j + 1] = rootCert;
					}
				}

				if (j == 0) {
					certificate = cert;
				}
			}

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

			ArrayList<List<CRL>> crlCollection = new ArrayList<List<CRL>>();

			for (int i = 0; i < certificateChain.length - 1; i++) {
				try {
					crlList = new DssHelper().readCRLsFromCert((X509Certificate) certificateChain[i]);
					
					if (crlList == null || crlList.size() <= 0) {
						break;
					}
					else {
						crlCollection.add(crlList);
					}	
				} catch (Exception e) {
					break;
				}
			}

			CertificateList[] certRevList = new CertificateList[crlCollection.size()];

			if (crlList == null || crlList.size() <= 0) {
				certRevList = null;
			} else {

				for (int i = 0; i < crlCollection.size(); i++) {
					X509CRL crl = (X509CRL) crlCollection.get(i).get(0);
					X509CRLHolder crlHolder = new X509CRLHolder(crl.getEncoded());
					certRevList[i] = crlHolder.toASN1Structure();
				}
			}

			List<OCSPResponse> ocspList = new ArrayList<OCSPResponse>();

			for (int i = 0; i < certificateChain.length; i++) {

				X509Certificate certTemp = (X509Certificate) certificateChain[i];

				if (i == 2 && certTemp == null) {
					break;
				}

				if (!certTemp.getIssuerDN().equals(certTemp.getSubjectDN())) {

					X509Certificate issuerCert = (X509Certificate) certificateChain[i + 1];
					if (issuerCert == null) {
						issuerCert = new GetOcspResp().getIssuerCert(certTemp);
					}
					try {
						ocspResp = new GetOcspResp().getOcspResp(certTemp, issuerCert);

						if (ocspResp != null) {
							ocspList.add(OCSPResponse.getInstance(ocspResp.getEncoded()));
						} else {
							break;
						}
					} catch (Exception e) {
						ocspResp = null;
						break;
					}
				}
			}

			if (ocspResp == null && certRevList == null) {
				throw new Exception("OcspResponse and CRLResponse error");
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

			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp = kpg.generateKeyPair();
			ContentSigner sha512Signer = new JcaContentSignerBuilder("SHA256WithRSA").build(kp.getPrivate());

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
			SignerIdentifier signatureId = new SignerIdentifier(
					new IssuerAndSerialNumber(certHolder.toASN1Structure()));

			String[] result = new String[2];
			result[0] = new String(Base64.encode(bytes));
			result[1] = new String(Base64.encode(signatureId.getEncoded()));

//			mobile.util mobile = new mobile.util();
//			mobile.GsoftSignedData(null, bytes,"resources/", "somchai.p12", "");
//			byte[] signature = mobile.getSignature();
//			
//			System.out.println("Signature: " + new String(Base64.encode(signature)));
//			System.out.println("SignID: " + new String(Base64.encode(signatureId.getEncoded())));
			return result;

		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			// e.printStackTrace();
			throw e;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			// e.printStackTrace();
			throw e;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			// e.printStackTrace();
			throw e;
		}
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
