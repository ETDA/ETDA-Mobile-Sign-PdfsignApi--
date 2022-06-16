package th.teda.pdfsigner.utils;
/**
 * 
 * @author itsaya
 * 
 */
public class HashTimeObject {
	private String hash;
	private Long time;

	public HashTimeObject() {
		super();
	}

	public HashTimeObject(String hash, Long time) {
		super();
		this.hash = hash;
		this.time = time;
	}

	public String getHash() {
		return hash;
	}

	public void setHash(String hash) {
		this.hash = hash;
	}

	public Long getTime() {
		return time;
	}

	public void setTime(Long time) {
		this.time = time;
	}
	
}
