package edu.vt.middleware;

import org.apache.commons.codec.binary.Base64InputStream;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * SAML digital signature validation test.
 *
 */
public class SamlSignTest
{
    public static void main(String[] args) throws Exception
    {
        if (args.length < 2) {
            System.out.println("USAGE: SamlSignTest path/to/response.b64 path/to/verify.crt");
            return;
        }
        File responseFile = new File(args[0]);
        File certFile = new File(args[1]);
        boolean valid;
        try {
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            Document doc = documentBuilderFactory.newDocumentBuilder().parse(
                    new Base64InputStream(new FileInputStream(responseFile)));
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
            doc.getDocumentElement().setIdAttribute("ID", true);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream(certFile));

            NodeList nodes = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (nodes == null || nodes.getLength() == 0) {
                System.out.println("Cannot find signature element in XML file");
                return;
            }
            DOMValidateContext ctx = new DOMValidateContext(cert.getPublicKey(), nodes.item(0));
            XMLSignatureFactory signature = XMLSignatureFactory.getInstance("DOM");
            XMLSignature xmlSignature = signature.unmarshalXMLSignature(ctx);
            valid = xmlSignature.validate(ctx);
        } catch (Exception e) {
            System.out.println("Error validating signature: " + e);
            valid = false;
        }
        System.out.println("Signature valid? " + (valid ? "Yes" : "No"));
    }
}
