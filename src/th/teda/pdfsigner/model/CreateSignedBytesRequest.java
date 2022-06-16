package th.teda.pdfsigner.model;

public class CreateSignedBytesRequest {

    private String signerCert;
    private String issuerCert;
    private String digest;

    public CreateSignedBytesRequest(){

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

    public String getDigest() {
        return digest;
    }

    public void setDigest(String digest) {
        this.digest = digest;
    }

}
