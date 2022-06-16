package th.teda.pdfsigner.controller;


import th.teda.pdfsigner.model.AttachSignatureRequest;
import th.teda.pdfsigner.model.AttachSignatureResponse;
import th.teda.pdfsigner.model.ComposeSignerInfoRequest;
import th.teda.pdfsigner.model.ComposeSignerInfoResponse;
import th.teda.pdfsigner.model.CreateSignedBytesRequest;
import th.teda.pdfsigner.model.CreateSignedBytesResponse;
import th.teda.pdfsigner.model.DigestDocRequest;
import th.teda.pdfsigner.model.DigestDocResponse;
import th.teda.pdfsigner.services.PdfSignerService;
import th.teda.pdfsigner.model.ReloadResponse;

import static th.teda.pdfsigner.results.Results.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@Component
@RestController
@RequestMapping("pdfSigner/v1")
public class PdfSignerController {

    Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    PdfSignerService pdfSignerService;

    @RequestMapping(value = "/digestDoc", method = RequestMethod.POST, produces = "application/json")
    public ResponseEntity<DigestDocResponse> pdfSignerDigestDocRequest(@RequestBody DigestDocRequest request) throws Exception {
        DigestDocResponse resController = new DigestDocResponse();

        try {

            logger.debug("************Start PdfSigner DigestDoc session()************");

            //InputVerify
            Boolean validInput = pdfSignerService.verifyDigestDocInput(request);
            if (!validInput) {
                logger.error("[digestDoc][Verify Input]: Verify Input FAILED");
            	resController.setDescription("Error : " + "[Verify Input]: Verify Input FAILED");
                resController.setStatus(FAILED_STATUS);
                logger.info("[pdfSigner]: DigestDoc ResultCode: " + resController.getStatus());
                logger.debug("*******************End PdfSigner DigestDoc session()********************");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resController);
            }

            //DigestDoc
            resController = pdfSignerService.digestDoc(request);
            
        } catch (Exception ex) {
        	resController.setDescription("Error : " + ex.getMessage());
            resController.setStatus(FAILED_STATUS);
            //resController.setDigest(undefined_error_message + ": " + ex.getMessage());
            //resController.setNamespace(undefined_error_code);
            ex.printStackTrace();
            logger.info("[pdfSigner]: DigestDoc ResultCode: " + resController.getStatus());
            logger.debug("*******************End PdfSigner DigestDoc session()********************");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(resController);
        }

        logger.info("[pdfSigner]: DigestDoc ResultCode: " + resController.getStatus());
        return ResponseEntity.status(HttpStatus.OK).body(resController);
    }
    
    @RequestMapping(value = "/createSignedBytes", method = RequestMethod.POST, produces = "application/json")
    public ResponseEntity<CreateSignedBytesResponse> pdfSignerCreateSignedBytesRequest(@RequestBody CreateSignedBytesRequest request) throws Exception {
        CreateSignedBytesResponse resController = new CreateSignedBytesResponse();

        try {

            logger.debug("************Start PdfSigner CreateSignedBytes session()************");

            //InputVerify
            Boolean validInput = pdfSignerService.verifyCreateSignedBytesInput(request);
            if (!validInput) {
                logger.error("[createSignedBytes][Verify Input]: Verify Input FAILED");
            	resController.setDescription("Error : " + "[Verify Input]: Verify Input FAILED");
                resController.setStatus(FAILED_STATUS);
                logger.info("[pdfSigner]: CreateSignedBytes ResultCode: " + resController.getStatus());
                logger.debug("*******************End PdfSigner CreateSignedBytes session()********************");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resController);
            }

            //CreateSignedBytes
            resController = pdfSignerService.createSignedBytes(request);
            
        } catch (Exception ex) {
        	resController.setDescription("Error : " + ex.getMessage());
            resController.setStatus(FAILED_STATUS);
            //resController.setDigest(undefined_error_message + ": " + ex.getMessage());
            //resController.setNamespace(undefined_error_code);
            ex.printStackTrace();
            logger.info("[pdfSigner]: CreateSignedBytes ResultCode: " + resController.getStatus());
            logger.debug("*******************End PdfSigner CreateSignedBytes session()********************");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(resController);
        }

        logger.info("[pdfSigner]: CreateSignedBytes ResultCode: " + resController.getStatus());
        return ResponseEntity.status(HttpStatus.OK).body(resController);
    }

    @RequestMapping(value = "/composeSignerInfo", method = RequestMethod.POST, produces = "application/json")
    public ResponseEntity<ComposeSignerInfoResponse> pdfSignerComposeSignerInfoRequest(@RequestBody ComposeSignerInfoRequest request) throws Exception {
        ComposeSignerInfoResponse resController = new ComposeSignerInfoResponse();

        try {

            logger.debug("************Start PdfSigner ComposeSignerInfo session()************");

            //InputVerify
            Boolean validInput = pdfSignerService.verifyComposeSignerInfoInput(request);
            if (!validInput) {
                logger.error("[composeSignerInfo][Verify Input]: Verify Input FAILED");
            	resController.setDescription("Error : " + "[Verify Input]: Verify Input FAILED");
                resController.setStatus(FAILED_STATUS);
                logger.info("[pdfSigner]: ComposeSignerInfo ResultCode: " + resController.getStatus());
                logger.debug("*******************End PdfSigner ComposeSignerInfo session()********************");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resController);
            }

            //ComposeSignerInfo
            resController = pdfSignerService.composeSignerInfo(request);
            
        } catch (Exception ex) {
        	resController.setDescription("Error : " + ex.getMessage());
            resController.setStatus(FAILED_STATUS);
            //resController.setDigest(undefined_error_message + ": " + ex.getMessage());
            //resController.setNamespace(undefined_error_code);
            ex.printStackTrace();
            logger.info("[pdfSigner]: ComposeSignerInfo ResultCode: " + resController.getStatus());
            logger.debug("*******************End PdfSigner ComposeSignerInfo session()********************");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(resController);
        }

        logger.info("[pdfSigner]: ComposeSignerInfo ResultCode: " + resController.getStatus());
        return ResponseEntity.status(HttpStatus.OK).body(resController);
    }

    @RequestMapping(value = "/attachSignature", method = RequestMethod.POST, produces = "application/json")
    public ResponseEntity<AttachSignatureResponse> pdfSignerAttachSignatureRequest(@RequestBody AttachSignatureRequest request) throws Exception {
        AttachSignatureResponse resController = new AttachSignatureResponse();

        try {

            logger.debug("************Start PdfSigner AttachSignature session()************");

            //InputVerify
            Boolean validInput = pdfSignerService.verifyAttachSignatureInput(request);
            if (!validInput) {
                logger.error("[Verify Input]: Verify Input FAILED");
            	resController.setDescription("Error : " + "[Verify Input]: Verify Input FAILED");
                resController.setStatus(FAILED_STATUS);
                logger.info("[pdfSigner]: AttachSignature ResultCode: " + resController.getStatus());
                logger.debug("*******************End PdfSigner AttachSignature session()********************");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resController);
            }

            //AttachSignature
            resController = pdfSignerService.attachSignature(request);
            
        } catch (Exception ex) {
        	resController.setDescription("Error : " + ex.getMessage());
            resController.setStatus(FAILED_STATUS);
            //resController.setDigest(undefined_error_message + ": " + ex.getMessage());
            //resController.setNamespace(undefined_error_code);
            ex.printStackTrace();
            logger.info("[pdfSigner]: AttachSignature ResultCode: " + resController.getStatus());
            logger.debug("*******************End PdfSigner AttachSignature session()********************");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(resController);
        }

        logger.info("[pdfSigner]: AttachSignature ResultCode: " + resController.getStatus());
        return ResponseEntity.status(HttpStatus.OK).body(resController);
    }

    @RequestMapping(value = "/reload", method = RequestMethod.POST, produces = "application/json")
    public ResponseEntity<ReloadResponse> pdfSignerReloadRequest() throws Exception {
        ReloadResponse resController = new ReloadResponse();

        try {

            logger.debug("************Start PdfSigner Reload session()************");

            //reload configuration
            resController = pdfSignerService.reloadConfig();
            
        } catch (Exception ex) {
        	resController.setDescription("Error : " + ex.getMessage());
            resController.setStatus(FAILED_STATUS);
            ex.printStackTrace();
            logger.info("[pdfSigner]: reload ResultCode: " + resController.getStatus());
            logger.debug("*******************End PdfSigner Reload session()********************");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(resController);
        }

        logger.info("[pdfSigner]: reload ResultCode: " + resController.getStatus());
        return ResponseEntity.status(HttpStatus.OK).body(resController);
    }
}
