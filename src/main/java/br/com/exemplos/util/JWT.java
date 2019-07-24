package br.com.exemplos.util;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import net.minidev.json.JSONObject;

public class JWT {
	
	public static void main(String[] args) throws Exception {
		JWT jwt = new JWT();
		System.out.println(jwt.assinarRSA("Leonardo", "chaves/private.der"));
	}
	
	public String obterPayloadNaoCriptografado(String jwt) throws ParseException{
		
		JWSObject objeto = JWSObject.parse(jwt);
		
		return new String(objeto.getPayload().toBytes());
		
	}
	
	public boolean verificarAssinaturaHMAC256(String jwt, String chave) throws JOSEException, ParseException{
		
		JWSVerifier verifier = new MACVerifier(chave.getBytes());
		
		SignedJWT jwtAssinado = SignedJWT.parse(jwt);
		
		return jwtAssinado.verify(verifier);
		
	}
	
	public boolean verificarAssinaturaRSA(String jwt, String caminhoChavePublica) throws JOSEException, ParseException, NoSuchAlgorithmException, InvalidKeySpecException{
		
		RSAPublicKey chavePublica = obterChavePublica(caminhoChavePublica);
		
		JWSVerifier verifier = new RSASSAVerifier(chavePublica);
		
		SignedJWT jwtAssinado = SignedJWT.parse(jwt);
		
		return jwtAssinado.verify(verifier);
		
	}
	
	public String criptografarRSA(String nome, String caminhoChavePublica) throws Exception{
		
		RSAPublicKey chavePublica = obterChavePublica(caminhoChavePublica);
		
		JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
			    .claim("nome", nome)
			    .build();
		
		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);
		
		EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);
		
		RSAEncrypter encrypter = new RSAEncrypter(chavePublica);
		
		jwt.encrypt(encrypter);

		return jwt.serialize();
	}
	
	public String assinarHMA256(String nome, String chave) throws JOSEException {
		
		JWSSigner signer = new MACSigner(chave.getBytes());
		
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
			.type(JOSEObjectType.JWT)
			.build();
		
		JSONObject jsonPayload = new JSONObject();
		
		jsonPayload.appendField("nome", nome);
		
		Payload payload = new Payload(jsonPayload.toJSONString().getBytes());
		
		JWSObject jwsObject = new JWSObject(header, payload);
		
		jwsObject.sign(signer);
		
		return jwsObject.serialize();
		
	}
	
	public String assinarRSA(String nome, String caminhoChavePrivada) throws Exception {
		
		RSAPrivateKey chavePrivada = obterChavePrivada(caminhoChavePrivada);
		
		JWSSigner signer = new RSASSASigner(chavePrivada);
		
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
			.type(JOSEObjectType.JWT)
			.build();
		
		JSONObject jsonPayload = new JSONObject();
		
		jsonPayload.appendField("nome", nome);
		
		Payload payload = new Payload(jsonPayload.toJSONString().getBytes());
		
		JWSObject jwsObject = new JWSObject(header, payload);
		
		jwsObject.sign(signer);
		
		return jwsObject.serialize();
		
	}
	
	public String descriptografarPayloadRSA(String token, String caminhoChavePrivada) throws Exception{
		
		RSAPrivateKey chavePrivada = obterChavePrivada(caminhoChavePrivada);
		
		RSADecrypter decrypter = new RSADecrypter(chavePrivada);

		EncryptedJWT jwt = EncryptedJWT.parse(token);

		jwt.decrypt(decrypter);
		
		return jwt.getPayload().toString();

	}
	
	public String descriptografarEVerificarAssinaturaRSA(String jwt, String caminhoChavePrivada, String caminhoChavePublica) throws Exception{
		
		RSAPrivateKey chavePrivada = obterChavePrivada(caminhoChavePrivada);
		
		RSAPublicKey chavePublica = obterChavePublica(caminhoChavePublica);
		
		JWEObject jweObject = JWEObject.parse(jwt);
		
		jweObject.decrypt(new RSADecrypter(chavePrivada));
		
		SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
		
		if(!signedJWT.verify(new RSASSAVerifier(chavePublica))){
			
			throw new RuntimeException("O token não está assinado como esperado");
			
		}
		
		return signedJWT.getPayload().toString();

	}
	
	public String descriptografarJwtRSA(String token, String caminhoChavePrivada) throws Exception{
		
		RSAPrivateKey chavePrivada = obterChavePrivada(caminhoChavePrivada);
		
		RSADecrypter decrypter = new RSADecrypter(chavePrivada);

		EncryptedJWT jwt = EncryptedJWT.parse(token);

		jwt.decrypt(decrypter);
		
		return jwt.serialize();

	}
	
	public String criptografarEAssinarRSA(String nome, String caminhoChavePrivada, String caminhoChavePublica) throws Exception {
		
		RSAPrivateKey chavePrivada = obterChavePrivada(caminhoChavePrivada);
		
		RSAPublicKey chavePublica = obterChavePublica(caminhoChavePublica);
		
		SignedJWT signedJWT = new SignedJWT(
			    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
			    new JWTClaimsSet.Builder()
			        .claim("nome", nome)
			        .build());
		
		signedJWT.sign(new RSASSASigner(chavePrivada));
		
		JWEObject jweObject = new JWEObject(
			    new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
			        .contentType("JWT") 
			        .build(),
			    new Payload(signedJWT));
		
		jweObject.encrypt(new RSAEncrypter(chavePublica));

		return jweObject.serialize();

	}
	
	private RSAPrivateKey obterChavePrivada(String caminho) throws Exception {

		byte[] bytes = obterArquivoResources(caminho);
			
	    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
	    
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    
	    return (RSAPrivateKey) kf.generatePrivate(spec);
	}
	
	public RSAPublicKey obterChavePublica(String caminho) throws NoSuchAlgorithmException, InvalidKeySpecException {

	    byte[] bytes = obterArquivoResources(caminho);
		
	    X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);

	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    
	    return (RSAPublicKey) kf.generatePublic(spec);
	}
	
	private byte[] obterArquivoResources(String caminho) {

        ClassLoader classLoader = getClass().getClassLoader();
        
        URL resource = classLoader.getResource(caminho);
        
        File arquivo = null;
        
        if (resource == null) {
        
        	throw new IllegalArgumentException("Arquivo não encontrado");
        
        } else {
        
        	arquivo = new File(resource.getFile());
        
        }
        
        try{
       
        	FileInputStream fis = new FileInputStream(arquivo);
        
		    DataInputStream dis = new DataInputStream(fis);
		    
		    byte[] bytes = new byte[(int) arquivo.length()];
		    
		    dis.readFully(bytes);
		    
		    dis.close();
		    
		    return bytes;
		    
        }catch(IOException e){
        	
        	throw new RuntimeException(e);
        	
        }

    }
	
	

}
