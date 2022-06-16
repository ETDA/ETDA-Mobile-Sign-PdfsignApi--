package th.teda.pdfsigner.model;

public class CreateSignedBytesResponse {

    private String description;
    private String status;
    private String signatureId;
    private String signedBytes;

    public CreateSignedBytesResponse(){

    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getSignatureId() {
        return signatureId;
    }

    public void setSignatureId(String signatureId) {
        this.signatureId = signatureId;
    }

    public String getSignedBytes() {
        return signedBytes;
    }

    public void setSignedBytes(String signedBytes) {
        this.signedBytes = signedBytes;
    }
}
