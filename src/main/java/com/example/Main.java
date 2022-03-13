package com.example;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.PSSSignatureSpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


public class Main {
	
	public static void main(String argv[]) {
		
		try {
			
			/* Cargar "provider" (sólo si no se usa el que viene por defecto) */
			//Security.addProvider(new BouncyCastleProvider()); 
			
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(512);
			
			KeyPair keyPair =  keyPairGenerator.generateKeyPair();
			
			System.out.println("====================================================");
			System.out.println(keyPair.getPublic());
			System.out.println("====================================================");
			System.out.println(keyPair.getPrivate());
			System.out.println("====================================================");
			
			try {
				X509Certificate certificate = obtenerCertificate(keyPair);
				System.out.println(certificate.toString());
			} catch (OperatorCreationException | CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	
	public static X509Certificate obtenerCertificate(KeyPair kPair) throws OperatorCreationException, CertificateException {
		 
		X509Certificate certificate = null;
		
		BigInteger serial = BigInteger.ONE;	//Número de serie. Se trata de un número único que identifica a todos los certificados de una misma autoridad de certificación.
		
		// Periodo de Validez
		Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
	    Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000);
	    
	    // Algoritmo
	    String algoritmo = "SHA1withRSA";
		
		X500NameBuilder nameBuilder = new X500NameBuilder();
		nameBuilder.addRDN(BCStyle.CN, "Test Certificate");
		nameBuilder.addRDN(BCStyle.O, "Mesosphere, Inc");
		nameBuilder.addRDN(BCStyle.L, "San Francisco");
		nameBuilder.addRDN(BCStyle.ST, "CA");
		nameBuilder.addRDN(BCStyle.C, "US");
		
		X500Name X500name = nameBuilder.build();
		
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(kPair.getPublic().getEncoded());
		
		X509v3CertificateBuilder certicateBuider = new X509v3CertificateBuilder(X500name,serial, startDate, endDate, X500name, publicKeyInfo);
		
		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(algoritmo);
		ContentSigner signer = csBuilder.build(kPair.getPrivate());
		
		X509CertificateHolder certHolder = certicateBuider.build(signer);
		
		certificate= new JcaX509CertificateConverter().getCertificate(certHolder);
		 
		return certificate;
		
	 }
	
	
	

}
