package sample;

import th.teda.pdfsigner.utils.SignHash;

public class TestSignDigest {

	public static void main(String[] args) throws Exception {

		SignHash signHash = new SignHash();

		String signInfo = signHash.signMsgDigest("P@ssw0rd", "resources/PKCS12/PDFSigner.p12",
				"Qf0SE5vJjsCAYQqZZrOoaYprShttZ+ON2mrvPMJZGQ4=");
		
		System.out.println("Signer Info: "+ signInfo);
	}
}
