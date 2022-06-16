package th.teda.pdfsigner.services;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.util.HashMap;

import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.util.encoders.Base64;
import org.json.JSONObject;

import th.teda.pdfsigner.configurations.Constants;
import th.teda.pdfsigner.results.Results;
import th.teda.pdfsigner.utils.HashTimeObject;

public class PDFSigner {

	public String attachSignature(String signerInfo, String signerCert, String issuerCert, String inputFile,
			String tsaUrl, String tsaKeyPath, String tsaKeyPass, String tsaKeyType, String timeString) {
		PDFSigner signer = new PDFSigner();
		String jsonString = null;
		try {
			String[] certString = new String[2];

			certString[0] = signerCert;
			certString[1] = issuerCert;

			//Long time = new Long(timeString);
			Long time = Long.parseLong(timeString);

			byte[] outputBytes = CreateCMSSignedData.signWithTSA(signerInfo, certString, inputFile, tsaUrl, tsaKeyPath,
					tsaKeyPass, tsaKeyType, time);
			String outputFile = new String(java.util.Base64.getEncoder().encode(outputBytes));
			HashMap<String, Object> jsonMap = new HashMap<String, Object>();
			jsonMap.put(Constants.LABEL_STATUS, Results.SUCCESS_STATUS);
			jsonMap.put(Constants.LABEL_OUTPUT_FILE, outputFile);
			JSONObject jsonResult = new JSONObject(jsonMap);
			jsonString = jsonResult.toString();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			jsonString = signer.writeError(e);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			jsonString = signer.writeError(e);
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			jsonString = signer.writeError(e);
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			jsonString = signer.writeError(e);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			jsonString = signer.writeError(e);
		}
		return jsonString;
	}

	public String composeSignerInfo(String signatureId, String signatureValue, String signedBytes) throws Exception {
		PDFSigner signer = new PDFSigner();
		String jsonString;
		try {
			ComposeSignerInfo compose = new ComposeSignerInfo();
			SignerInfo signerInfo = compose.composeSignerInfo(signatureId, signatureValue, signedBytes);
			byte[] encoded;

			encoded = Base64.encode(signerInfo.getEncoded());

			HashMap<String, Object> jsonMap = new HashMap<String, Object>();
			jsonMap.put(Constants.LABEL_STATUS, Results.SUCCESS_STATUS);
			jsonMap.put(Constants.LABEL_SIGNERINFO, new String(encoded));

			JSONObject jsonResult = new JSONObject(jsonMap);
			jsonString = jsonResult.toString();
			System.out.println(jsonString);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			// e.printStackTrace();
			jsonString = signer.writeError(e);
		}
		return jsonString;
	}

	public String digestDocument(byte[] inputBytes) throws IOException, Exception {
		PDFSigner signer = new PDFSigner();
		String jsonString;
		try {
			CreateEncapsulatedInfo createEncap = new CreateEncapsulatedInfo();
			HashTimeObject encapData = createEncap.getData(inputBytes);
			
			HashMap<String, Object> jsonMap = new HashMap<String, Object>();
			jsonMap.put(Constants.LABEL_STATUS, Results.SUCCESS_STATUS);
			jsonMap.put(Constants.LABEL_DIGEST, encapData.getHash());
			jsonMap.put(Constants.LABEL_TIME, encapData.getTime());

			JSONObject jsonResult = new JSONObject(jsonMap);
			jsonString = jsonResult.toString();
			//System.out.println(jsonString);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			jsonString = signer.writeError(e);
		}
		return jsonString;
	}

	public String createSignedBytes(String digest, String signerCert, String issuerCert) {
		PDFSigner signer = new PDFSigner();
		String jsonString = null;
		
		try {

			String[] certString = new String[2];
			// TODO Auto-generated method stub
			certString[0] = signerCert;
			certString[1] = issuerCert;

			CreateSignedBytes createSignedBytes = new CreateSignedBytes();
			String[] result = createSignedBytes.createSignedBytes(digest, certString);

			HashMap<String, Object> jsonMap = new HashMap<String, Object>();
			jsonMap.put(Constants.LABEL_STATUS, Results.SUCCESS_STATUS);
			jsonMap.put(Constants.LABEL_SIGNEDBYTES, result[0]);
			jsonMap.put(Constants.LABEL_SIGNATURE_ID, result[1]);

			JSONObject jsonResult = new JSONObject(jsonMap);
			jsonString = jsonResult.toString();
			//System.out.println(jsonString);

		} catch (Exception e) {
			// TODO Auto-generated catch block
			jsonString = signer.writeError(e);
		}
		return jsonString;
	}

	public String writeError(Exception e) {

		e.printStackTrace();

		HashMap<String, Object> errorMap = null;
		JSONObject errorOut = null;
		String errorMessage = null;
		String errorString = null;

		errorMap = new HashMap<String, Object>();
		errorMessage = Constants.LABEL_DESCRIPTION_ERROR + e.getMessage();
		
		errorMap.put(Constants.LABEL_STATUS, Results.FAILED_STATUS);
		errorMap.put(Constants.LABEL_DESCRIPTION, errorMessage);

		errorOut = new JSONObject(errorMap);
		errorString = errorOut.toString();

		return errorString;
	}

}
