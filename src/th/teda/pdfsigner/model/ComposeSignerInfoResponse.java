package th.teda.pdfsigner.model;

public class ComposeSignerInfoResponse {

    private String description;
    private String status;
    private String signerInfo;

    public ComposeSignerInfoResponse(){

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

    public String getSignerInfo() {
        return signerInfo;
    }

    public void setSignerInfo(String signerInfo) {
        this.signerInfo = signerInfo;
    }

}
