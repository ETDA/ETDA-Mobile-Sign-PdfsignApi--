package th.teda.pdfsigner.services;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.DefaultCMSSignatureEncryptionAlgorithmFinder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

public class ComposeSignerInfo {
	public SignerInfo composeSignerInfo(String signatureId, String signatureValue, String signedBytes) throws Exception {

		SignerIdentifier signId;
		SignerInfo signerInfo = null;
		try {
			signId = new SignerIdentifier(ASN1Primitive.fromByteArray(Base64.decode(signatureId.getBytes())));

			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp = kpg.generateKeyPair();
			ContentSigner sha512Signer = new JcaContentSignerBuilder("SHA256WithRSA").build(kp.getPrivate());

			DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
			AlgorithmIdentifier digesterAlgId = digAlgFinder.find(sha512Signer.getAlgorithmIdentifier());
//			DigestCalculatorProvider digesterProv = new JcaDigestCalculatorProviderBuilder().build();
			DefaultCMSSignatureEncryptionAlgorithmFinder sigEncAlgFinder = new DefaultCMSSignatureEncryptionAlgorithmFinder();
			AlgorithmIdentifier digestEncryptAl = sigEncAlgFinder
					.findEncryptionAlgorithm(sha512Signer.getAlgorithmIdentifier());

			ASN1Set signedAttrASN = (ASN1Set) ASN1Set.fromByteArray(Base64.decode(signedBytes.getBytes()));

			signerInfo = new SignerInfo(signId, digesterAlgId, signedAttrASN, digestEncryptAl,
					new DEROctetString(Base64.decode(signatureValue.getBytes())), null);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			throw e;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			throw e;
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			throw e;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			throw e;
		}

		return signerInfo;

	}
}
