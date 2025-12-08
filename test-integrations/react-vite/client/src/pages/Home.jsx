import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import LoginDialog from '../components/LoginDialog';

const Home = () => {
    const { isAuthenticated, userInfo } = useAuth();
    const [showLoginDialog, setShowLoginDialog] = useState(false);

    return (
        <div className="page home-page">
            <div className="hero">
                <h1>Goiabada OAuth2/OIDC demo</h1>
                <p className="hero-subtitle">
                    A sample React application demonstrating authentication with Goiabada
                </p>

                {!isAuthenticated && (
                    <button
                        className="btn btn-primary btn-lg"
                        onClick={() => setShowLoginDialog(true)}
                    >
                        Sign in
                    </button>
                )}
            </div>

            <div className="features-grid">
                <div className="feature-card">
                    <div className="feature-icon">
                        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                        </svg>
                    </div>
                    <h3>OAuth2/OIDC Authentication</h3>
                    <p>
                        Secure authentication using the Authorization Code flow with PKCE.
                        Supports multiple ACR levels for step-up authentication.
                    </p>
                </div>

                <div className="feature-card">
                    <div className="feature-icon">
                        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                            <circle cx="9" cy="7" r="4" />
                            <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
                            <path d="M16 3.13a4 4 0 0 1 0 7.75" />
                        </svg>
                    </div>
                    <h3>Group-Based Access Control</h3>
                    <p>
                        Protect routes based on user group membership. Demonstrates
                        role-based access control with the &apos;managers&apos; group.
                    </p>
                </div>

                <div className="feature-card">
                    <div className="feature-icon">
                        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <polyline points="16 18 22 12 16 6" />
                            <polyline points="8 6 2 12 8 18" />
                        </svg>
                    </div>
                    <h3>Token inspector</h3>
                    <p>
                        Explore your ID token, access token, and refresh token.
                        See decoded claims and understand what information is available.
                    </p>
                </div>

                <div className="feature-card">
                    <div className="feature-icon">
                        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M23 4v6h-6" />
                            <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
                        </svg>
                    </div>
                    <h3>Silent token refresh</h3>
                    <p>
                        Automatic token refresh before expiration keeps your session
                        active without interruption.
                    </p>
                </div>
            </div>

            {isAuthenticated && userInfo && (
                <div className="welcome-card">
                    <h2>Welcome back, {userInfo.name || userInfo.email}!</h2>
                    <p>You are authenticated. Explore the protected areas of this demo.</p>

                    <div className="user-details">
                        <div className="detail-row">
                            <span className="detail-label">Email:</span>
                            <span className="detail-value">{userInfo.email}</span>
                        </div>
                        {userInfo.groups && userInfo.groups.length > 0 && (
                            <div className="detail-row">
                                <span className="detail-label">Groups:</span>
                                <span className="detail-value">
                                    {userInfo.groups.map(g => (
                                        <span key={g} className="badge">{g}</span>
                                    ))}
                                </span>
                            </div>
                        )}
                    </div>
                </div>
            )}

            <div className="info-section">
                <h2>About this demo</h2>
                <p>
                    This application demonstrates how to integrate a React SPA with Goiabada
                    using the Backend-for-Frontend (BFF) pattern. The backend handles all OAuth
                    flows and stores tokens securely in server-side sessions.
                </p>

                <h3>Available routes</h3>
                <ul className="route-list">
                    <li>
                        <Link to="/"><code>/</code></Link> - This home page (public)
                    </li>
                    <li>
                        <Link to="/protected"><code>/protected</code></Link> - Requires authentication
                    </li>
                    <li>
                        <Link to="/managers"><code>/managers</code></Link> - Requires authentication + &apos;managers&apos; group
                    </li>
                    <li>
                        <Link to="/admin"><code>/admin</code></Link> - Requires authentication + &apos;backend:admin&apos; scope
                    </li>
                    <li>
                        <Link to="/tokens"><code>/tokens</code></Link> - Token inspector (requires authentication)
                    </li>
                </ul>
            </div>

            <LoginDialog
                isOpen={showLoginDialog}
                onClose={() => setShowLoginDialog(false)}
            />
        </div>
    );
};

export default Home;
