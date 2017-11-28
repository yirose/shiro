package cn.sh.shiro.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@RequestMapping("/shiro")
public class ShiroHandler {

	@RequestMapping("/login")
	public String login(@RequestParam("username") String username,
			@RequestParam("password") String password){
		Subject currentUser = SecurityUtils.getSubject();
		
        if (!currentUser.isAuthenticated()) {
            UsernamePasswordToken token = new UsernamePasswordToken(username,password);
            token.setRememberMe(true);
            try {
            	//执行登陆
                currentUser.login(token);
            } catch (UnknownAccountException uae){
            	System.out.println("There is no user with username of " + token.getPrincipal());
            } catch (IncorrectCredentialsException ice) {
            	System.out.println("Password for account " + token.getPrincipal() + " was incorrect!");

            } catch (LockedAccountException lae){
            	System.out.println("The account for username " + token.getPrincipal() + " is locked.  " +
                        "Please contact your administrator to unlock it.");
            }
            catch (AuthenticationException ae){
            	System.out.println("登录失败" + ae.getMessage());
            }
        }
		return "redirect:unauthorized.jsp";
	}
}