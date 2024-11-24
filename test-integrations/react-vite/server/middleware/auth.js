import { validateTokensExpiration, refreshTokens, checkGroupMembership } from '../utils/tokenUtils.js';

export const isAuthenticated = async (req, res, next) => {
    try {
        if (!req.session?.tokens) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        const validation = await validateTokensExpiration(req.session.tokens);        

        if (!validation.isValid) {
            // Check if we can refresh the tokens
            if (validation.canRefresh) {
                console.log('Refreshing tokens...');
                const refreshResult = await refreshTokens(req.session);                

                if (!refreshResult.success) {
                    console.log('Token refresh failed:', refreshResult.error);
                    return res.status(401).json({
                        error: 'Authentication expired and refresh failed',
                        details: refreshResult.error
                    });
                }

                // Explicitly save the updated session after refresh
                await new Promise((resolve, reject) => {
                    req.session.save((err) => {
                        if (err) {
                            console.error('Failed to save session after token refresh:', err);
                            reject(err);
                        } else {
                            console.log('Session saved successfully after token refresh');
                            resolve();
                        }
                    });
                });

                // Verify the new tokens are valid
                const newValidation = await validateTokensExpiration(req.session.tokens);
                if (!newValidation.isValid) {
                    return res.status(401).json({
                        error: 'New tokens invalid after refresh',
                        details: newValidation.error
                    });
                }
            } else {
                console.log('Token validation failed:', validation.error);
                return res.status(401).json({
                    error: validation.error,
                    requiresLogin: true
                });
            }
        }      

        next();
    } catch (error) {
        console.error('Authentication check failed:', error);
        return res.status(500).json({ error: 'Internal server error during authentication check' });
    }
};

export const hasRequiredRole = (requiredRole) => {
    return async (req, res, next) => {
        try {
            // First ensure the user is authenticated
            await new Promise((resolve, reject) => {
                isAuthenticated(req, res, (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });

            // If we get here, user is authenticated, now check role
            const roleCheck = checkGroupMembership(req.session.tokens.id_token, requiredRole);

            if (!roleCheck.hasGroup) {
                return res.status(403).json({
                    error: 'Insufficient permissions',
                    details: `User does not have required role: ${requiredRole}`,
                    userGroups: roleCheck.groups || []
                });
            }

            // Add the user's groups to the request object for potential use in route handlers
            req.userGroups = roleCheck.groups;

            next();
        } catch (error) {
            // If error was already handled by isAuthenticated, we'll just return
            if (res.headersSent) return;

            console.error('Role verification failed:', error);
            return res.status(500).json({
                error: 'Failed to verify permissions',
                details: error.message
            });
        }
    };
};

// Optional: Middleware for checking multiple roles (ANY of the roles)
export const hasAnyRole = (requiredRoles) => {
    return async (req, res, next) => {
        try {
            // First ensure the user is authenticated
            await new Promise((resolve, reject) => {
                isAuthenticated(req, res, (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });

            // Get all user groups
            const groupsCheck = checkGroupMembership(req.session.tokens.id_token);
            const userGroups = groupsCheck.groups || [];

            // Check if user has any of the required roles
            const hasRequiredRole = requiredRoles.some(role => userGroups.includes(role));

            if (!hasRequiredRole) {
                return res.status(403).json({
                    error: 'Insufficient permissions',
                    details: `User does not have any of the required roles: ${requiredRoles.join(', ')}`,
                    userGroups
                });
            }

            // Add the user's groups to the request object
            req.userGroups = userGroups;

            next();
        } catch (error) {
            // If error was already handled by isAuthenticated, we'll just return
            if (res.headersSent) return;

            console.error('Role verification failed:', error);
            return res.status(500).json({
                error: 'Failed to verify permissions',
                details: error.message
            });
        }
    };
};

// Optional: Middleware for checking multiple roles (ALL roles required)
export const hasAllRoles = (requiredRoles) => {
    return async (req, res, next) => {
        try {
            // First ensure the user is authenticated
            await new Promise((resolve, reject) => {
                isAuthenticated(req, res, (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });

            // Get all user groups
            const groupsCheck = checkGroupMembership(req.session.tokens.id_token);
            const userGroups = groupsCheck.groups || [];

            // Check if user has all required roles
            const hasAllRequiredRoles = requiredRoles.every(role => userGroups.includes(role));

            if (!hasAllRequiredRoles) {
                return res.status(403).json({
                    error: 'Insufficient permissions',
                    details: `User does not have all required roles: ${requiredRoles.join(', ')}`,
                    userGroups
                });
            }

            // Add the user's groups to the request object
            req.userGroups = userGroups;

            next();
        } catch (error) {
            // If error was already handled by isAuthenticated, we'll just return
            if (res.headersSent) return;

            console.error('Role verification failed:', error);
            return res.status(500).json({
                error: 'Failed to verify permissions',
                details: error.message
            });
        }
    };
};