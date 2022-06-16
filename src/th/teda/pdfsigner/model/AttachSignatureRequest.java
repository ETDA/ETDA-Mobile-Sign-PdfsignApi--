package th.teda.pdfsigner.model;

public class AttachSignatureRequest {

	private String signerInfo;
	private String signerCert;
    private String issuerCert;
	private String inputFile;
	private String timestampRequired;
	private String timeString;
    public AttachSignatureRequest(){

    }

    public String getSignerInfo() {
        return signerInfo;
    }

    public void setSignerInfo(String signerInfo) {
        this.signerInfo = signerInfo;
    }

    public String getSignerCert() {
        return signerCert;
    }

    public void setSignerCert(String signerCert) {
        this.signerCert = signerCert;
    }

    public String getIssuerCert() {
        return issuerCert;
    }

    public void setIssuerCert(String issuerCert) {
        this.issuerCert = issuerCert;
    }

    public String getInputFile() {
        return inputFile;
    }

    public void setInputFile(String inputFile) {
        this.inputFile = inputFile;
    }

    public String getTimestampRequired() {
        return timestampRequired;
    }

    public void setTimestampRequired(String timestampRequired) {
        this.timestampRequired = timestampRequired;
    }

    public String getTimeString() {
        return timeString;
    }

    public void setTimeString(String timeString) {
        this.timeString = timeString;
    }

}
