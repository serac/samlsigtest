package edu.vt.middleware;

import org.apache.commons.codec.binary.Base64InputStream;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * SAML digital signature validation test.
 *
 */
public class SamlSignTest {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("USAGE: SamlSignTest path/to/response.b64 path/to/verify.crt");
            return;
        }
        File responseFile = new File(args[0]);
        File certFile = new File(args[1]);
        boolean valid;
        try {
            DocumentBuilder builder = getSAMLDocumentBuilder();
            Document doc = builder.parse(
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

    private static Source[] readSchemas() {
        Source[] sources = null;
        try {
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            sources = new Source[] {
                    new StreamSource(new InputStreamReader(cl.getResourceAsStream("saml-schema-assertion-2.0.xsd"), "UTF-8")),
                    new StreamSource(new InputStreamReader(cl.getResourceAsStream("saml-schema-protocol-2.0.xsd"), "UTF-8")),
                    new StreamSource(new InputStreamReader(cl.getResourceAsStream("xmldsig-core-schema.xsd"), "UTF-8")),
                    new StreamSource(new InputStreamReader(cl.getResourceAsStream("xenc-schema.xsd"), "UTF-8")) };
        } catch (Exception e) {

        }
        return sources;

    }

    private static DocumentBuilder getSAMLDocumentBuilder() throws SAXException, ParserConfigurationException {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);

        Source[] sources = readSchemas();
        if (sources != null) {
            SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = schemaFactory.newSchema(sources);
            documentBuilderFactory.setSchema(schema);
        }

        return documentBuilderFactory.newDocumentBuilder();
    }
}
