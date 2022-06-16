package th.teda.pdfsigner.services;

import th.teda.pdfsigner.model.AttachSignatureRequest;
import th.teda.pdfsigner.model.AttachSignatureResponse;
import th.teda.pdfsigner.model.ComposeSignerInfoRequest;
import th.teda.pdfsigner.model.ComposeSignerInfoResponse;
import th.teda.pdfsigner.model.CreateSignedBytesRequest;
import th.teda.pdfsigner.model.CreateSignedBytesResponse;
import th.teda.pdfsigner.model.DigestDocRequest;
import th.teda.pdfsigner.model.DigestDocResponse;
import th.teda.pdfsigner.model.ReloadResponse;

public interface PdfSignerService {

    Boolean verifyDigestDocInput(DigestDocRequest request) throws Exception;
    DigestDocResponse digestDoc(DigestDocRequest request) throws Exception;
    Boolean verifyCreateSignedBytesInput(CreateSignedBytesRequest request) throws Exception;
    CreateSignedBytesResponse createSignedBytes(CreateSignedBytesRequest request) throws Exception;
    Boolean verifyComposeSignerInfoInput(ComposeSignerInfoRequest request) throws Exception;
    ComposeSignerInfoResponse composeSignerInfo(ComposeSignerInfoRequest request) throws Exception;
    Boolean verifyAttachSignatureInput(AttachSignatureRequest request) throws Exception;
    AttachSignatureResponse attachSignature(AttachSignatureRequest request) throws Exception;
    ReloadResponse reloadConfig() throws Exception;
}
