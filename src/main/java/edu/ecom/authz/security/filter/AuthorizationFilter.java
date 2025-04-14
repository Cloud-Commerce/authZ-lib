//package edu.ecom.authz.security.filter;
//
//import edu.ecom.authz.security.dto.TokenDetails;
//import edu.ecom.authz.security.service.AuthorizationService;
//import edu.ecom.authz.security.service.RequiredRoleFinderService;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import java.io.IOException;
//import java.util.Optional;
//import org.springframework.http.HttpStatus;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//@Component
//public class AuthorizationFilter extends OncePerRequestFilter {
//    private final AuthorizationService authorizationService;
//    private final RequiredRoleFinderService roleFinderService;
//
//    public AuthorizationFilter(AuthorizationService authorizationService,
//        RequiredRoleFinderService roleFinderService) {
//        this.authorizationService = authorizationService;
//      this.roleFinderService = roleFinderService;
//    }
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request,
//                                   HttpServletResponse response,
//                                   FilterChain filterChain)
//        throws ServletException, IOException {
//
//        // Skip authorization for certain paths (login, health check, etc.)
//        if (shouldSkipAuthorization(request)) {
//            filterChain.doFilter(request, response);
//            return;
//        }
//
//        // Get the required role from route configuration (could be from a config map)
//        String requiredRole = roleFinderService.getRequiredRoleForRoute(request.getRequestURI());
//
//        String authHeader = request.getHeader("Authorization");
//        if (Optional.ofNullable(authHeader).filter(t -> t.startsWith("Bearer ")).isEmpty()) {
//            response.sendError(HttpStatus.FORBIDDEN.value(), "Missing or invalid Authorization header");
//        } else {
//            String token = authHeader.split(" ")[1];
//            TokenDetails tokenDetails = authorizationService.getAuthorizedClaims(token, requiredRole);
//            if (tokenDetails.isGenuine()) {
//                if ("NEW".equals(tokenDetails.getState())) {
//                    response.setHeader("Authorization", "Bearer " + tokenDetails.getToken());
//                }
//                filterChain.doFilter(request, response);
//            } else {
//                response.sendError(HttpStatus.FORBIDDEN.value(), "Access Denied");
//            }
//        }
//    }
//
//    private boolean shouldSkipAuthorization(HttpServletRequest request) {
//        // Implement logic to skip auth for certain paths
//        return false;
//    }
//
//}