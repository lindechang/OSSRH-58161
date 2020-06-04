package com.cocofei.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.cocofei.jwt.JwtUserInfoFactory.SECRET;


/**
 * @Author: lindec
 * @Email:lindec@163.com
 * @Date: 上午9:20 2018/5/15 Created with Intellij IDEA
 * @Description:
 */
public class JwtTokenUtil implements Serializable {

    private static final long serialVersionUID = -3301605591108950415L;

    //    private static final String CLAIM_KEY_USERNAME = "username";
    private static final String CLAIM_KEY_USERNAME = "sub";
    private static final String CLAIM_KEY_CREATED = "created";


    //private static String secret ="com-zeroing-sdk-jwt-secret";


    private static final Long expiration = 86400L;

    /**
     * 生成截止时间
     *
     * @return
     */
    private Date generateExpirationDate() {
        return new Date(System.currentTimeMillis() + expiration * 1000);
    }

    private Date generateExpirationDate(Long tokinaga) {
        return new Date(System.currentTimeMillis() + tokinaga);
    }

    /**
     * 生成关联用户的Token
     * 默认一天时间
     * @param userDetails
     * @return
     */
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<String, Object>();
        claims.put(CLAIM_KEY_USERNAME, userDetails.getUsername());
        claims.put(CLAIM_KEY_CREATED, new Date());
        return createToken(claims, expiration * 1000);
    }

    /**
     * 生成要加密的Token
     * 默认一天时间
     * @param content 加密内容
     * @return
     */
    public String generateToken(String content) {
        Map<String, Object> claims = new HashMap<String, Object>();
        claims.put(CLAIM_KEY_USERNAME, content);
        claims.put(CLAIM_KEY_CREATED, new Date());
        return createToken(claims, expiration * 1000);
    }

    /**
     * jjwt库生成Token
     */
    private String createToken(Map<String, Object> claims, long time) {
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(generateExpirationDate(time))
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .compact();
    }


    /**
     * 更新TOKEN
     * 注意：当token无效时不更新,应该确保Token有效是做更新
     *
     * @param token
     * @return
     */
    public String refreshToken(String token, long time) {
        String refreshedToken;
        try {
            final Claims claims = getClaimsFromToken(token);
            claims.put(CLAIM_KEY_CREATED, new Date());
            refreshedToken = createToken(claims, time);
        } catch (Exception e) {
            refreshedToken = null;
        }
        return refreshedToken;
    }


    /**
     * 获得用户username
     *
     * @param token
     * @return
     */
    public String getUsernameFromToken(String token) {
        String username;
        try {
            final Claims claims = getClaimsFromToken(token);
            username = claims.getSubject();
        } catch (Exception e) {
            username = null;
        }
        return username;
    }

    /**
     * 获得TOKEN创建时间
     *
     * @param token
     * @return
     */
    private Date getCreatedDateFromToken(String token) {
        Date created;
        try {
            final Claims claims = getClaimsFromToken(token);
            created = new Date((Long) claims.get(CLAIM_KEY_CREATED));
        } catch (Exception e) {
            created = null;
        }
        return created;
    }


    /**
     * 获得TOKEN期限时间
     *
     * @param token
     * @return
     */
    private Date getExpirationDateFromToken(String token) {
        Date expiration;
        try {
            final Claims claims = getClaimsFromToken(token);
            expiration = claims.getExpiration();
        } catch (Exception e) {
            expiration = null;
        }
        return expiration;
    }

    /**
     * 获得Claims
     *
     * @param token
     * @return
     */
    private Claims getClaimsFromToken(String token) {
        Claims claims;
        try {
            claims = Jwts.parser()
                    .setSigningKey(SECRET)
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            claims = null;
        }
        return claims;
    }

    /**
     * TOKEN是否超时
     * true 已失效 false 未失效
     */
    public Boolean isTokenExpired(String token) {
        Date expiration = getExpirationDateFromToken(token);
        if (expiration != null) {
            return expiration.before(new Date());
        }
        return true;
    }

    /**
     * TOKEN创建时间是否在修改密码之前
     *
     * @param created
     * @param lastPasswordReset
     * @return true 则TOKEN是在修改密码之前创建的，未无效。反之，TOKEN有效
     */
    private Boolean isCreatedBeforeLastPasswordReset(Date created, Date lastPasswordReset) {
        return (lastPasswordReset != null && created.before(lastPasswordReset));
    }


    /**
     * TOKEN是否更新为可用（是否有效，TOKEN超时或者TOKEN创建时间在修改密码之前，都判断为无效）
     *
     * @param token
     * @param lastPasswordReset
     * @return false TOKEN无效。返之有效
     */
    public Boolean canTokenBeRefreshed(String token, Date lastPasswordReset) {
        final Date created = getCreatedDateFromToken(token);
        if (created != null) {
            return !isCreatedBeforeLastPasswordReset(created, lastPasswordReset)
                    && !isTokenExpired(token);
        }
        return false;
    }


    /**
     * TOKEN验证 是否有效
     *
     * @param token
     * @param userDetails
     * @return
     */
    public Boolean validateToken(String token, UserDetails userDetails) {
        JwtUserInfo user = (JwtUserInfo) userDetails;
        final String username = getUsernameFromToken(token);
        final Date created = getCreatedDateFromToken(token);
        if (username == null || created == null) {
            return false;
        }
        return username.equals(user.getUsername()) && canTokenBeRefreshed(token, new Date(user.getLastPasswordResetDate()));
    }
}