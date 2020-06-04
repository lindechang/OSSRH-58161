package com.cocofei.jwt;

import com.alibaba.fastjson.JSONObject;
import org.bson.types.ObjectId;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.stream.Collectors;

/**
 * @Author: lindec
 * @Email:lindec@163.com
 * @Date: 下午12:49 2018/5/14 Created with Intellij IDEA
 * @Description:
 */
public class JwtUserInfoFactory {

    public static final String SECRET = "com-zeroing-sdk-jwt-secret";

    private JwtUserInfoFactory() {
    }

    public static JwtUserInfo createByUsername(JSONObject object) {
        List<String> roles = (List<String>) object.get("roles");
        return new JwtUserInfo(
                (ObjectId) object.get("id"),
                object.get("uid").toString(),
                MD5Util.encode(SECRET),
                //object.get("password").toString(),
                //mapToGrantedAuthorities(user.getRoles().stream().map(Role::getName).collect(Collectors.toList())),
                mapToGrantedAuthorities(roles),
                (Long) object.get("time"));
    }


    private static List<GrantedAuthority> mapToGrantedAuthorities(List<String> authorities) {
        return authorities.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
