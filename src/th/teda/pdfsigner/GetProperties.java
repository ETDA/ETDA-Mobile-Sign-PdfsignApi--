package th.teda.pdfsigner;


import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Properties;

public class GetProperties {


    public static Properties getProperty(String propName) throws Exception {
        String resourceName = propName; // could also be a constant
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        Properties props = new Properties();
        InputStream resourceStream = null;

        try {
            resourceStream = loader.getResourceAsStream(resourceName);
            props.load(resourceStream);
        } catch (Exception e) {
            throw new Exception(e.getMessage());

        } finally {
            if (resourceStream != null)
                resourceStream.close();
        }
        return props;
    }

    public static Properties getPropertyFromPath(String path) throws Exception {
        Properties props = new Properties();
        InputStream resourceStream = null;

        try {
            resourceStream = new FileInputStream(new File(path));
            props.load(resourceStream);
        } catch (Exception e) {
            throw new Exception(e.getMessage());

        } finally {
            if (resourceStream != null)
                resourceStream.close();
        }
        return props;
    }
}
