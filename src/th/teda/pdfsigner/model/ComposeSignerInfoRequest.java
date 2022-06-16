package th.teda.pdfsigner.model;

public class ComposeSignerInfoRequest {

    private String signatureId;
    private String signatureValue;
    private String signedBytes;

    public ComposeSignerInfoRequest(){

    }

    public String getSignatureId() {
        return signatureId;
    }

    public void setSignatureId(String signatureId) {
        this.signatureId = signatureId;
    }

    public String getSignatureValue() {
        return signatureValue;
    }

    public void setSignatureValue(String signatureValue) {
        this.signatureValue = signatureValue;
    }

    public String getSignedBytes() {
        return signedBytes;
    }

    public void setSignedBytes(String signedBytes) {
        this.signedBytes = signedBytes;
    }

}
