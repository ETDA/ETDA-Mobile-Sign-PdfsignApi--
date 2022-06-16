package th.teda.pdfsigner.services;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Calendar;
import java.util.Date;

import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.util.encoders.Base64;

import th.teda.pdfsigner.utils.HashTimeObject;

public class CreateEncapsulatedInfo implements SignatureInterface {

	HashTimeObject createEncapsulatedInfo(byte[] inputBytes) throws IOException, Exception {
		PDDocument doc = null;
		try {
			doc = PDDocument.load(inputBytes);
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			PDSignature signature = new PDSignature();
			signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
			signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
			Calendar cal = Calendar.getInstance();
			Date date = cal.getTime();
			long time = date.getTime();
			doc.setDocumentId(time);
			
			cal.setTime(date);
			signature.setSignDate(cal);

			COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
			catalogDict.setNeedToBeUpdated(true);

			SignatureOptions signatureOptions = new SignatureOptions();
			signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 12);

			doc.addSignature(signature, this, signatureOptions);

			InputStream is = doc.getEncapsulatedContent(bos);

			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] inputByteArray = IOUtils.toByteArray(is);
			byte[] digest = md.digest(inputByteArray);

			byte[] encoded = Base64.encode(digest);
			//FOR TESTING
			//System.out.println(new String(java.util.Base64.getDecoder().decode(bos.toByteArray())));

			return new HashTimeObject(new String(encoded), time);
		} catch (Exception e) {
			// e.printStackTrace();
			// return null;
			throw e;
		} finally {
			if (doc != null) {
				doc.close();
			}
		}
	}

//	HashTimeObject createEncapsulatedInfo(byte[] inputBytes) throws IOException, Exception {
//		PDDocument doc = null;
//		try {
//			doc = PDDocument.load(inputBytes);
//			OutputStream bos = new ByteArrayOutputStream();
//			PDSignature signature = new PDSignature();
//			signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
//			signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
//			Calendar cal = Calendar.getInstance();
//			Date date = cal.getTime();
//			long time = date.getTime();
//
//			cal.setTime(date);
//			signature.setSignDate(cal);
//
//			COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
//			catalogDict.setNeedToBeUpdated(true);
//
//			SignatureOptions signatureOptions = new SignatureOptions();
//			signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 12);
//
//			doc.addSignature(signature, this, signatureOptions);
//
//			InputStream is = doc.getEncapsulatedContent(bos);
//
//			MessageDigest md = MessageDigest.getInstance("SHA-256");
//			byte[] inputByteArray = IOUtils.toByteArray(is);
//			byte[] digest = md.digest(inputByteArray);
//
//			byte[] encoded = Base64.encode(digest);
//
//			return new HashTimeObject(new String(encoded), time);
//		} catch (Exception e) {
//			// e.printStackTrace();
//			// return null;
//			throw e;
//		} finally {
//			if (doc != null) {
//				doc.close();
//			}
//		}
//	}

	@Override
	public byte[] sign(InputStream content) throws IOException {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * 
	 * @param inputFileName
	 * @param outputFile
	 * @return String[] {encapsulate data, Sign Date}
	 * @throws IOException
	 */
	public HashTimeObject getData(byte[] inputBytes) throws IOException, Exception {

		return new CreateEncapsulatedInfo().createEncapsulatedInfo(inputBytes);
	}

}
