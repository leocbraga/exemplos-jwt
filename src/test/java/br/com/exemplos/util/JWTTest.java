package br.com.exemplos.util;

import java.text.ParseException;

import org.junit.Assert;
import org.junit.Test;

import com.nimbusds.jose.JOSEException;

public class JWTTest {
	
	private static final String CHAVE_HMAC256 = "estaChaveDeveConter32CaracteresVouEscrevendoSoParaTestar";
	
	private JWT jwt = new JWT();
	
	@Test
	public void testarCodificacaoTokenComAssinaturaHMAC25() throws JOSEException{
		
		String token = jwt.assinarHMA256("Leonardo", CHAVE_HMAC256);
		
		Assert.assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJub21lIjoiTGVvbmFyZG8ifQ.G07nsJUSQrDpej4kEuFWI2l8TkGHH0cvKvrTfeoX3XY", token);
		
	}
	
	@Test
	public void testarCodificacaoTokenComAssinaturaRSA() throws Exception{
		
		String token = jwt.assinarRSA("Leonardo", "chaves/privada.der");
		
		Assert.assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJub21lIjoiTGVvbmFyZG8ifQ.A1-EXXWAolWI662ZJxVOLQMZAN0nmvpEmst59BWZsNgS_hYYXuvc8AvFF0OyviMGBfjoq26qDRRhAf6-LBF0r99zTTjbbKXmOZSxpN1Ngnv5mrXL38Vi4m8v3dSsnRUbXFDMuAofKasZWxpbIKElkvv4kFRvSIhE9y_IcXrLGezLF_ldVTtNJiPfAUfHlkDp5C9D4DWzPsVM_nTwuP1MmLslKtsAmPwcznSuCzj_RAvhpIbvtLuesqWlvItL5MJXNukEq0CGSHOXDW7d7jgrDk5ATp84yzS9PduH-OmYh8Ty-LA1MJtatnD6zacLI0UeFPNjmbbSCGjWQvyuw1HQ4A", token);
		
	}
	
	@Test
	public void testarAssinaturaValidaHMAC25() throws JOSEException, ParseException{
		
		String token = jwt.assinarHMA256("Leonardo", CHAVE_HMAC256);
		
		Assert.assertTrue(jwt.verificarAssinaturaHMAC256(token, CHAVE_HMAC256));
		
	}
	
	@Test
	public void testarAssinaturaValidaRSA() throws Exception{
		
		String token = jwt.assinarRSA("Leonardo", "chaves/privada.der");
		
		Assert.assertTrue(jwt.verificarAssinaturaRSA(token, "chaves/publica.der"));
		
	}
	
	@Test
	public void testarAssinaturaInvalidaHMAC25() throws JOSEException, ParseException{
		
		String token = jwt.assinarHMA256("Leonardo", CHAVE_HMAC256);
		
		Assert.assertFalse(jwt.verificarAssinaturaHMAC256(token, "estaChaveInvalidaDeveConter32CaracteresVouEscrevendoSoParaTestar"));
		
	}
	
	@Test
	public void testarObtencaoPayloadSemCriptografia() throws JOSEException, ParseException{
		
		String token = jwt.assinarHMA256("Leonardo", CHAVE_HMAC256); 
		
		String payload = jwt.obterPayloadNaoCriptografado(token);
		
		Assert.assertEquals("{\"nome\":\"Leonardo\"}", payload);
		
	}
	
	@Test
	public void testarCriptografiaRSA() throws Exception{
		
//		String token = jwt.criptografarRSA("Leonardo", "chaves/publica.der"); 
//		
//		Assert.assertEquals("eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.kWknuEcXm-qyQ9ZAJXGKiSOyowT3EwZWek5SlyCj9QLvu4TtBzi3Cwlkh98xIFPkmLYo828a8lX1h7S0jcfkku81Xs1MPABe5Fzeh2fRczcHJzHk-cUC3fQF59mZAAjzACO9mIKdsa431RChQ9gXvmHn33a_EafOg6QRue9h7rG9VJBH_fHzGrugfYE7icp_HwjleMDe_cSiqg8MHBYnTDm61Vk2BECLy40nrxipAEk6RySN-I5e7V9K2TfJYod9S2mw_BVoAcpkQafP-AqbP2Ws3B8R9Ti5E_d4zg5feSArL8O-EKh-l8NGyOcEPU3Z-7r596mvkI_m1x0-QvsRgg.vJRn8t-aWlHNYfH1.yH5blyzrZVNpyPMmloFXA799mw.5Q26FYdn53PH-dtKl1hNQg", token);
		
	}
	
	@Test
	public void testarDescriptografiaPayloadRSA() throws Exception{
		
		String token = jwt.criptografarRSA("Leonardo", "chaves/publica.der"); 
		
		String payload = jwt.descriptografarPayloadRSA(token, "chaves/privada.der");
		
		Assert.assertEquals("{\"nome\":\"Leonardo\"}", payload);
		
	}
	
	@Test
	public void testarCriptografiaEAssinaturaRSA() throws Exception{
		
		String token = jwt.criptografarEAssinarRSA("Leonardo", "chaves/privada.der", "chaves/publica.der"); 
		
//		Assert.assertEquals("eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.Eyl4ZlUxIuLBcYiY6FiXezsQEVr_4IBbKsEhlp112sCLdzrT4LysfYVF8NsqANoxEDVbgO-j2c0UfndWn2TOFqrHCNPa_NBwxLu_UPxiDaSGpj-Fr-FvsYqesKP18adWxmo69MIzSulr9CQZhewd0vf75t003tUV2FZ0c41Krbw11lqxCiHymGiHl8IjlQj3gIHssBFiaQNeVNeNuihXuaQcph8xr3D9kMBGEiEC4KeLtQjx2chEOGjw9hAN9_iQJYDxWMqFdWlNqt_FhE1B6KhRwQGgZYB2VVaOKqef0RLdH20gxJqqLgCE06KpvF1BO-ESdyv2Fkfi0MTPZqYurg.6lQWNRPdQUYyfv6K.0So0KyzK4aftx6U26HIFlk3BRUYpjAKv43FprEBmyloix7rh_oRCksViK_ovXNcELCP-mFC9UTh3_IInR4vTTBFOF9-iBCNoxkexgaNn5vWgci5N8YAagZWhr2DeripMF8kJ6hivxRURTYE3IAlCZ42B0J_WsfSA2E2o-B5wu-BXBHEk-TjEslQ223-SDukVwgu9Ls2D3XN_74w03CSqrkw3X7noWTI8Tae036cbq8KyguDNEjAj28Tju9yQU0jICxo1b4RLpEY4kOwcSpj9aP_jvY-B18V1nJ3N1nmk4NWezHaXszR5S1xgkr93ge6VsjTwO-UuDWYQ2qyCMhMUhVVA6XTNDMDwTTSzVdXwJA0TF85R8J-o-2X2nMoAWY4LP_8ESue239bpNmkFJ6jylMwM-u2Z-6Se_4GXbTkwFK-s67DXTsor84WurlT1wKHgvB2aincapsXY7anYkTaeEDHElHGbJxVLy6f1Iv2QROblzTCJILpbr09LoxEBDsX2PzAT7pSb.asMtPxyNjn-cLuueeJ5q8A", token);
		
	}
	
	@Test
	public void testarDescriptografiaEAssinaturaRSA() throws Exception{
		
		String token = jwt.criptografarEAssinarRSA("Leonardo", "chaves/privada.der", "chaves/publica.der");
		
		String payload = jwt.descriptografarEVerificarAssinaturaRSA(token, "chaves/privada.der", "chaves/publica.der"); 
		
		System.out.println(payload);
		
		Assert.assertEquals("{\"nome\":\"Leonardo\"}", payload);
		
	}
	
}
