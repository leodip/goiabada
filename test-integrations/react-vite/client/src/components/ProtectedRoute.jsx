import { Navigate, useLocation, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const AccessDenied = ({ reason, requirement }) => {
  return (
    <div className="page access-denied-page">
      <div className="access-denied-card">
        <div className="access-denied-icon">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10" />
            <line x1="4.93" y1="4.93" x2="19.07" y2="19.07" />
          </svg>
        </div>
        <h1>Access denied</h1>
        <p className="access-denied-message">
          You don&apos;t have permission to access this page.
        </p>
        <div className="access-denied-details">
          <p><strong>Reason:</strong> {reason}</p>
          <p><strong>Required:</strong> <code>{requirement}</code></p>
        </div>
        <Link to="/" className="btn btn-primary">
          Go to home
        </Link>
      </div>
    </div>
  );
};

export const ProtectedRoute = ({ children, requiredRole = null, requiredScope = null }) => {
  const { isAuthenticated, isLoading, userInfo, tokens } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return <div>Loading...</div>;
  }

  if (!isAuthenticated) {
    return <Navigate to="/" state={{ from: location }} replace />;
  }

  // Check for required role (group membership)
  if (requiredRole && (!userInfo?.groups || !userInfo.groups.includes(requiredRole))) {
    return (
      <AccessDenied
        reason="You are not a member of the required group"
        requirement={`Group: ${requiredRole}`}
      />
    );
  }

  // Check for required scope in access token
  if (requiredScope) {
    const accessTokenScope = tokens?.access_token?.payload?.scope || '';
    const scopes = accessTokenScope.split(' ');
    if (!scopes.includes(requiredScope)) {
      return (
        <AccessDenied
          reason="Your access token does not include the required scope"
          requirement={`Scope: ${requiredScope}`}
        />
      );
    }
  }

  return children;
};
