package th.teda.pdfsigner.services;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;

import java.util.HashMap;
import java.util.Properties;

import th.teda.pdfsigner.configurations.Configurations;
import th.teda.pdfsigner.configurations.Constants;
import th.teda.pdfsigner.GetProperties;
import th.teda.pdfsigner.model.AttachSignatureRequest;
import th.teda.pdfsigner.model.AttachSignatureResponse;
import th.teda.pdfsigner.model.ComposeSignerInfoRequest;
import th.teda.pdfsigner.model.ComposeSignerInfoResponse;
import th.teda.pdfsigner.model.CreateSignedBytesRequest;
import th.teda.pdfsigner.model.CreateSignedBytesResponse;
import th.teda.pdfsigner.model.DigestDocRequest;
import th.teda.pdfsigner.model.DigestDocResponse;
import th.teda.pdfsigner.model.ReloadResponse;
import th.teda.pdfsigner.results.Results;

@Service
public class PdfSignerServiceImpl implements PdfSignerService {
	
	private static Properties conProp;

	PDFSigner signer = null;
	
    Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public Boolean verifyDigestDocInput(DigestDocRequest request) {

        boolean isInputFileHasText = StringUtils.hasText(request.getInputFile());
        
        return isInputFileHasText;
    }

    @Override
    public Boolean verifyCreateSignedBytesInput(CreateSignedBytesRequest request) {

        boolean isSignerCertHasText = StringUtils.hasText(request.getSignerCert());
        boolean isIssuerCertHasText = StringUtils.hasText(request.getIssuerCert());
        boolean isDigestHasText = StringUtils.hasText(request.getDigest());
        
        return isSignerCertHasText && isIssuerCertHasText && isDigestHasText;
    }

    @Override
    public Boolean verifyComposeSignerInfoInput(ComposeSignerInfoRequest request) {

        boolean isSignatureIdHasText = StringUtils.hasText(request.getSignatureId());
        boolean isSignatureValueHasText = StringUtils.hasText(request.getSignatureValue());
        boolean isSignedBytesHasText = StringUtils.hasText(request.getSignedBytes());
        
        return isSignatureIdHasText && isSignatureValueHasText && isSignedBytesHasText;
    }

    @Override
    public Boolean verifyAttachSignatureInput(AttachSignatureRequest request) {

        boolean isSignerInfoHasText = StringUtils.hasText(request.getSignerInfo());
        boolean isSignerCertHasText = StringUtils.hasText(request.getSignerCert());
        boolean isIssuerCertHasText = StringUtils.hasText(request.getIssuerCert());
        boolean isInputFileHasText = StringUtils.hasText(request.getInputFile());
        boolean isTimestampRequiredHasText = StringUtils.hasText(request.getTimestampRequired());
        boolean isTimeStringHasText = StringUtils.hasText(request.getTimeString());
        
        boolean result = false;
        
        String timestampRequiredString = request.getTimestampRequired();
        if (timestampRequiredString.equals("0") || timestampRequiredString.equals("1")) {
        	result = isSignerInfoHasText && isSignerCertHasText && isIssuerCertHasText && isInputFileHasText && isTimestampRequiredHasText && isTimeStringHasText;
        } else {
        	result = false;
        }
        return result;
    }

    @Override
    public DigestDocResponse digestDoc(DigestDocRequest request) throws Exception {

        String inputFile = null;
        String jsonResult = null;
        JSONObject jsonObj = null;
        DigestDocResponse response = null;
        
        try {

            inputFile = request.getInputFile();
			byte[] decodedBytes = java.util.Base64.getDecoder().decode(inputFile.getBytes(StandardCharsets.UTF_8));
            jsonResult = signer.digestDocument(decodedBytes);
            jsonObj = new JSONObject(jsonResult);
            response = new DigestDocResponse();
            if (jsonObj.has(Constants.LABEL_DESCRIPTION)) {
            	response.setDescription(jsonObj.getString(Constants.LABEL_DESCRIPTION));
            }
            if (jsonObj.has(Constants.LABEL_STATUS)) {
                response.setStatus(jsonObj.getString(Constants.LABEL_STATUS));
            }
            if (jsonObj.has(Constants.LABEL_DIGEST)) {
                response.setDigest(jsonObj.getString(Constants.LABEL_DIGEST));
            }
            if (jsonObj.has(Constants.LABEL_TIME)) {
                response.setTime(jsonObj.getLong(Constants.LABEL_TIME));
            }

        } catch (Exception ex) {
            logger.error("[" + "]: PDFSigner digestDoc Unknown ERROR: " + ex.getMessage());
            ex.printStackTrace();
            response = new DigestDocResponse();
            response.setDescription("Error : " + ex.getMessage());
            response.setStatus(Results.FAILED_STATUS);
        }

        return response;

    }

    @Override
    public CreateSignedBytesResponse createSignedBytes(CreateSignedBytesRequest request) throws Exception {

        String signerCert = null;
        String issuerCert = null;
        String digest = null;
        String jsonResult = null;
        JSONObject jsonObj = null;
        CreateSignedBytesResponse response = null;
        
        try {
            signerCert = request.getSignerCert();
            issuerCert = request.getIssuerCert();
            digest = request.getDigest();
            jsonResult = signer.createSignedBytes(digest, signerCert, issuerCert);
            jsonObj = new JSONObject(jsonResult);
            response = new CreateSignedBytesResponse();
            if (jsonObj.has(Constants.LABEL_DESCRIPTION)) {
            	response.setDescription(jsonObj.getString(Constants.LABEL_DESCRIPTION));
            }
            if (jsonObj.has(Constants.LABEL_STATUS)) {
                response.setStatus(jsonObj.getString(Constants.LABEL_STATUS));
            }
            if (jsonObj.has(Constants.LABEL_SIGNATURE_ID)) {
                response.setSignatureId(jsonObj.getString(Constants.LABEL_SIGNATURE_ID));
            }
            if (jsonObj.has(Constants.LABEL_SIGNEDBYTES)) {
                response.setSignedBytes(jsonObj.getString(Constants.LABEL_SIGNEDBYTES));
            }

        } catch (Exception ex) {
            logger.error("[" + "]: PDFSigner CreateSignedBytes ERROR: " + ex.getMessage());
            ex.printStackTrace();
            response = new CreateSignedBytesResponse();
            response.setDescription("Error : " + ex.getMessage());
            response.setStatus(Results.FAILED_STATUS);
        }

        return response;

    }

    @Override
    public ComposeSignerInfoResponse composeSignerInfo(ComposeSignerInfoRequest request) throws Exception {

        String signatureId = null;
        String signatureValue = null;
        String signedBytes = null;
        String jsonResult = null;
        JSONObject jsonObj = null;
        ComposeSignerInfoResponse response = null;
        
        try {
            signatureId = request.getSignatureId();
            signatureValue = request.getSignatureValue();
            signedBytes = request.getSignedBytes();
            jsonResult = signer.composeSignerInfo(signatureId, signatureValue, signedBytes);
            jsonObj = new JSONObject(jsonResult);
            response = new ComposeSignerInfoResponse();
            if (jsonObj.has(Constants.LABEL_DESCRIPTION)) {
            	response.setDescription(jsonObj.getString(Constants.LABEL_DESCRIPTION));
            }
            if (jsonObj.has(Constants.LABEL_STATUS)) {
                response.setStatus(jsonObj.getString(Constants.LABEL_STATUS));
            }
            if (jsonObj.has(Constants.LABEL_SIGNERINFO)) {
                response.setSignerInfo(jsonObj.getString(Constants.LABEL_SIGNERINFO));
            }

        } catch (Exception ex) {
            logger.error("[" + "]: PDFSigner ComposeSignerInfo ERROR: " + ex.getMessage());
            ex.printStackTrace();
            response = new ComposeSignerInfoResponse();
            response.setDescription("Error : " + ex.getMessage());
            response.setStatus(Results.FAILED_STATUS);
        }

        return response;

    }

    @Override
    public AttachSignatureResponse attachSignature(AttachSignatureRequest request) throws Exception {

    	String signerInfo = null;
    	String signerCert = null;
    	String issuerCert = null;
    	String inputFile = null;
        String timestampRequired = null;
        String tsaUrl = null;
    	String tsaKeyPath = null;
    	String tsaKeyPass = null;
    	String tsaKeyType = null;
        String timeString = null;
        String jsonResult = null;
        JSONObject jsonObj = null;
        AttachSignatureResponse response = null;
        
        try {
        	signerInfo = request.getSignerInfo();
        	signerCert = request.getSignerCert();
        	issuerCert = request.getIssuerCert();
            inputFile = request.getInputFile();
            timestampRequired = request.getTimestampRequired();
            tsaKeyType = "PKCS12";
            timeString = request.getTimeString();

            if (timestampRequired.equals("1")) {
            	tsaUrl = conProp.getProperty(Constants.LABEL_TSA_URL);
            	tsaKeyPath = conProp.getProperty(Constants.LABEL_TSA_KEY_PATH);
            	tsaKeyPass = conProp.getProperty(Constants.LABEL_TSA_KEY_PASSWORD);
            } else if (timestampRequired.equals("0")) {
               	tsaUrl = "";
            	tsaKeyPath = "";
            	tsaKeyPass = "";
            }

            jsonResult = signer.attachSignature(signerInfo, signerCert, issuerCert, inputFile, tsaUrl, tsaKeyPath, tsaKeyPass, tsaKeyType, timeString);
            jsonObj = new JSONObject(jsonResult);
            response = new AttachSignatureResponse();
            if (jsonObj.has(Constants.LABEL_DESCRIPTION)) {
            	response.setDescription(jsonObj.getString(Constants.LABEL_DESCRIPTION));
            }
            if (jsonObj.has(Constants.LABEL_STATUS)) {
                response.setStatus(jsonObj.getString(Constants.LABEL_STATUS));
            }
            if (jsonObj.has(Constants.LABEL_OUTPUT_FILE)) {
                response.setOutputFile(jsonObj.getString(Constants.LABEL_OUTPUT_FILE));
            }

        } catch (Exception ex) {
            logger.error("[" + "]: PDFSigner AttachSignature ERROR: " + ex.getMessage());
            ex.printStackTrace();
            response = new AttachSignatureResponse();
            response.setDescription("Error : " + ex.getMessage());
            response.setStatus(Results.FAILED_STATUS);
        }

        return response;

    }

    @Override
    public ReloadResponse reloadConfig() throws Exception {
        
        ReloadResponse response = null;

        try {
        	conProp = GetProperties.getPropertyFromPath(Configurations.configPath);
            response = new ReloadResponse();           
            response.setStatus(Results.SUCCESS_STATUS);
        } catch (Exception ex) {
            logger.error("[" + "]: PDFSigner Reload ERROR: " + ex.getMessage());
            ex.printStackTrace();
            response = new ReloadResponse();
            response.setDescription("Error : " + ex.getMessage());
            response.setStatus(Results.FAILED_STATUS);
        }

        logger.debug("*******************End session()********************");
        return response;

    }

	public PdfSignerServiceImpl() throws Exception {
		try {
			init();
		} catch (Exception e) {
			throw e;
		}
	}

	private void init() throws Exception {

		signer = new PDFSigner();
        conProp = GetProperties.getPropertyFromPath(Configurations.configPath);
	}


	public String writeError(String erMsg) {

		return writeError(new Exception(erMsg));
	}

	public String writeError(Exception e) {

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
		//System.out.println(errorString);
		
		return errorString;
	}

	public String generateWarning(String warnMsg) {

		HashMap<String, Object> warnMap = null;
		JSONObject warnOut = null;
		String warnMessage = null;
		String warnString = null;

		warnMap = new HashMap<String, Object>();
		warnMessage = warnMsg;

		warnMap.put(Constants.LABEL_STATUS, Results.WARNING_STATUS);
		warnMap.put(Constants.LABEL_DESCRIPTION, warnMessage);

		warnOut = new JSONObject(warnMap);
		warnString = warnOut.toString();
		
		return warnString;
	}

}
